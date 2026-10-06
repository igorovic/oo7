// org.freedesktop.Secret.Prompt

use std::{
    future::Future,
    os::fd::AsFd,
    pin::Pin,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use formatx::formatx;
use gettextrs::gettext;
use oo7::{Secret, dbus::ServiceError};
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, OnceCell},
    task::AbortHandle,
};
use zbus::{
    interface,
    names::OwnedUniqueName,
    object_server::SignalEmitter,
    zvariant::{ObjectPath, Optional, OwnedObjectPath, OwnedValue, Value},
};

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
use crate::gnome::prompter::{GNOMEPrompterCallback, GNOMEPrompterProxy};
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
use crate::plasma::prompter::PlasmaPrompterCallback;
use crate::{
    collection::Collection,
    error::custom_service_error,
    service::{PrompterType, Service},
    socket_prompter::{self, Operation, Reply, Request, RequestType},
};

#[zbus::proxy(
    interface = "org.freedesktop.secrets.CliPrompter",
    default_service = "org.freedesktop.secrets.CliPrompter",
    default_path = "/org/freedesktop/secrets/CliPrompter"
)]
trait CliPrompter {
    #[zbus(no_autostart)]
    async fn prompt(
        &self,
        label: &str,
        description: &str,
    ) -> zbus::Result<(zbus::zvariant::OwnedFd, bool)>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptRole {
    Unlock,
    CreateCollection,
    ChangePassword,
    /// Whether a client may use items whose keyring is already unlocked
    /// (per-client access; only the socket prompter asks it).
    Access,
}

/// What a prompt asks after the keyring's password, with per-client access:
/// whether its client may use `objects` for `operation`.
#[derive(Debug, Clone)]
pub struct AccessStep {
    pub operation: Operation,
    pub objects: Vec<OwnedObjectPath>,
}

/// A boxed future that represents the action to be taken when a prompt
/// completes
pub type PromptActionFuture =
    Pin<Box<dyn Future<Output = Result<OwnedValue, ServiceError>> + Send + 'static>>;

/// Represents the action to be taken when a prompt completes
pub struct PromptAction {
    /// The async function to execute when the prompt is accepted
    action: Box<dyn FnOnce(Option<Secret>) -> PromptActionFuture + Send>,
}

impl PromptAction {
    /// Create a new prompt action from a closure that takes an optional secret
    /// and returns a future
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: FnOnce(Option<Secret>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OwnedValue, ServiceError>> + Send + 'static,
    {
        Self {
            action: Box::new(move |secret| Box::pin(f(secret))),
        }
    }

    /// Execute the action with the provided secret
    pub async fn execute(self, secret: Option<Secret>) -> Result<OwnedValue, ServiceError> {
        (self.action)(secret).await
    }
}

#[derive(Clone)]
pub struct Prompt {
    service: Service,
    role: PromptRole,
    path: OwnedObjectPath,
    /// The label of the collection/keyring being prompted for
    label: String,
    /// The collection for Unlock prompts (needed for secret validation)
    collection: Option<crate::collection::Collection>,
    /// GNOME Specific
    #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
    gnome_callback: Arc<OnceCell<GNOMEPrompterCallback>>,
    /// KDE Plasma Specific
    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    plasma_callback: Arc<OnceCell<PlasmaPrompterCallback>>,
    /// The action to execute when the prompt completes
    action: Arc<Mutex<Option<PromptAction>>>,
    /// The client that caused the prompt: named in the socket prompter's
    /// requests, and allowed by the access step
    client: Option<OwnedUniqueName>,
    /// Asked after the password, with per-client access
    access: Option<AccessStep>,
    /// The result sent with a dismissal: of the type the method that made the
    /// prompt returns on success, since libsecret checks the type before it
    /// looks at `dismissed` (an `ao` for `CreateItem` left `secret-tool store`
    /// waiting forever)
    dismissed_result: fn() -> OwnedValue,
    /// Socket prompter specific: its conversation, aborted by `Dismiss`
    socket_started: Arc<AtomicBool>,
    socket_task: Arc<std::sync::Mutex<Option<AbortHandle>>>,
}

#[cfg(any(
    feature = "gnome_openssl_crypto",
    feature = "gnome_native_crypto",
    feature = "plasma_native_crypto",
    feature = "plasma_openssl_crypto"
))] // User has to enable at least one prompt backend
#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    pub async fn prompt(
        &self,
        window_id: Optional<&str>,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), ServiceError> {
        if self.service.prompter_socket().is_some() {
            return self.start_socket_prompt().await;
        }

        if self.role == PromptRole::Access {
            return Err(custom_service_error(
                "Access prompts need the socket prompter.",
            ));
        }

        let window_id = (*window_id).and_then(|w| ashpd::WindowIdentifierType::from_str(w).ok());
        let peer_info = match header.sender() {
            Some(sender) => self
                .service
                .session_from_sender(sender)
                .await
                .and_then(|s| s.peer_info().cloned()),
            None => None,
        };

        match self.service.prompter_type(peer_info.as_ref()).await {
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            PrompterType::Plasma => self.prompt_plasma(window_id).await,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            PrompterType::GNOME => self.prompt_gnome(window_id).await,
            PrompterType::Cli => self.prompt_cli().await,
            #[allow(unreachable_patterns)]
            _ => Err(custom_service_error(
                "No prompt backend available in the current environment.",
            )),
        }
    }

    pub async fn dismiss(&self) -> Result<(), ServiceError> {
        // Closes the socket prompter's connection: the prompter closes its
        // dialog on EOF.
        if let Some(task) = self.socket_task.lock().unwrap().take() {
            task.abort();
        }

        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        if let Some(callback) = self.plasma_callback.get() {
            let emitter = SignalEmitter::from_parts(
                self.service.connection().clone(),
                callback.path().clone(),
            );
            PlasmaPrompterCallback::dismiss(&emitter).await?;
        }

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        if let Some(_callback) = self.gnome_callback.get() {
            // TODO: figure out if we should destroy the un-export the callback
            // here?
        }

        self.service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await?;
        self.service.remove_prompt(&self.path).await;

        Ok(())
    }

    #[zbus(signal, name = "Completed")]
    pub async fn completed(
        signal_emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

impl Prompt {
    pub async fn new(
        service: Service,
        role: PromptRole,
        label: String,
        collection: Option<crate::collection::Collection>,
    ) -> Self {
        // A keyring with no file yet has no password to check: what unlocks it
        // is the password it will be created with, so ask for a new one.
        let role = match &collection {
            Some(collection) if role == PromptRole::Unlock && collection.is_new().await => {
                PromptRole::CreateCollection
            }
            _ => role,
        };
        let index = service.prompt_index();
        Self {
            path: OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/prompt/p{index}"))
                .unwrap(),
            service,
            role,
            label,
            collection,
            #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
            gnome_callback: Default::default(),
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            plasma_callback: Default::default(),
            action: Arc::new(Mutex::new(None)),
            client: None,
            access: None,
            dismissed_result: empty_result,
            socket_started: Default::default(),
            socket_task: Default::default(),
        }
    }

    pub fn with_client(mut self, client: OwnedUniqueName) -> Self {
        self.client = Some(client);
        self
    }

    /// For a method whose prompt completes with one object path
    /// (`CreateItem`, `CreateCollection`): dismissed, it sends `/`.
    pub fn with_path_result(mut self) -> Self {
        self.dismissed_result = no_path_result;
        self
    }

    pub fn with_access(mut self, access: AccessStep) -> Self {
        self.access = Some(access);
        self
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    pub fn role(&self) -> PromptRole {
        self.role
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    fn collection(&self) -> Option<&crate::collection::Collection> {
        self.collection.as_ref()
    }

    /// Set the action to execute when the prompt completes
    pub async fn set_action(&self, action: PromptAction) {
        *self.action.lock().await = Some(action);
    }

    /// Take the action, consuming it so it can only be executed once
    async fn take_action(&self) -> Option<PromptAction> {
        self.action.lock().await.take()
    }

    pub async fn on_unlock_collection(&self, secret: Option<Secret>) -> Result<bool, ServiceError> {
        debug_assert_eq!(self.role, PromptRole::Unlock);

        // Get the collection to validate the secret
        let collection = self.collection().expect("Unlock requires a collection");
        let label = self.label();

        let is_valid = if let Some(ref secret) = secret {
            // Validate the secret using the already-open keyring
            let keyring_guard = collection.keyring.read().await;
            let valid = keyring_guard
                .as_ref()
                .unwrap()
                .validate_secret(secret)
                .await
                .map_err(|err| {
                    custom_service_error(&format!(
                        "Failed to validate secret for {label} keyring: {err}."
                    ))
                })?;
            drop(keyring_guard);
            valid
        } else {
            // No secret means unencrypted -> validate items are plaintext
            let keyring_guard = collection.keyring.read().await;
            let valid = keyring_guard
                .as_ref()
                .unwrap()
                .validate_unencrypted()
                .await
                .map_err(|err| {
                    custom_service_error(&format!(
                        "Failed to validate unencrypted keyring {label}: {err}."
                    ))
                })?;
            drop(keyring_guard);
            valid
        };

        if is_valid {
            tracing::debug!("Keyring secret matches for {label}.");

            let Some(action) = self.take_action().await else {
                return Err(custom_service_error(
                    "Prompt action was already executed or not set",
                ));
            };

            // Execute the unlock action after successful validation
            let result_value = action.execute(secret).await?;

            let prompt_path = self.path().to_owned();
            let signal_emitter = self.service.signal_emitter(&prompt_path)?;
            tokio::spawn(async move {
                tracing::debug!("Unlock prompt completed.");
                let _ = Prompt::completed(&signal_emitter, false, result_value).await;
            });
            Ok(true)
        } else {
            tracing::error!("Keyring {label} failed to unlock, incorrect secret.");

            Ok(false)
        }
    }

    pub async fn on_create_collection(&self, secret: Option<Secret>) -> Result<(), ServiceError> {
        debug_assert_eq!(self.role, PromptRole::CreateCollection);

        let Some(action) = self.take_action().await else {
            return Err(custom_service_error(
                "Prompt action was already executed or not set",
            ));
        };

        // Execute the collection creation action with the secret
        match action.execute(secret).await {
            Ok(collection_path_value) => {
                tracing::info!("CreateCollection action completed successfully");

                let signal_emitter = self.service.signal_emitter(self.path().to_owned())?;

                tokio::spawn(async move {
                    tracing::debug!("CreateCollection prompt completed.");
                    let _ = Prompt::completed(&signal_emitter, false, collection_path_value).await;
                });
                Ok(())
            }
            Err(err) => Err(custom_service_error(&format!(
                "Failed to create collection: {err}."
            ))),
        }
    }

    pub async fn on_change_password(&self, secret: Option<Secret>) -> Result<(), ServiceError> {
        debug_assert_eq!(self.role, PromptRole::ChangePassword);

        let Some(action) = self.take_action().await else {
            return Err(custom_service_error(
                "Prompt action was already executed or not set",
            ));
        };

        // Execute the change password action with the new secret
        match action.execute(secret).await {
            Ok(result) => {
                tracing::info!("ChangePassword action completed successfully");

                let signal_emitter = self.service.signal_emitter(self.path().to_owned())?;

                tokio::spawn(async move {
                    tracing::debug!("ChangePassword prompt completed.");
                    let _ = Prompt::completed(&signal_emitter, false, result).await;
                });
                Ok(())
            }
            Err(err) => Err(custom_service_error(&format!(
                "Failed to change password: {err}."
            ))),
        }
    }

    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    async fn prompt_plasma(
        &self,
        window_id: Option<ashpd::WindowIdentifierType>,
    ) -> Result<(), ServiceError> {
        if self.plasma_callback.get().is_some() {
            return Err(custom_service_error(
                "A prompt callback is ongoing already.",
            ));
        }

        let callback = PlasmaPrompterCallback::new(self.service.clone(), self.path.clone()).await;
        let path = OwnedObjectPath::from(callback.path().clone());

        let _ = self.plasma_callback.set(callback.clone());
        self.service
            .object_server()
            .at(&path, callback.clone())
            .await?;
        tracing::debug!("Prompt `{}` created.", self.path);

        callback.start(&self.role, window_id, &self.label).await
    }

    #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
    async fn prompt_gnome(
        &self,
        window_id: Option<ashpd::WindowIdentifierType>,
    ) -> Result<(), ServiceError> {
        if self.gnome_callback.get().is_some() {
            return Err(custom_service_error(
                "A GNOME prompt callback is ongoing already.",
            ));
        };

        let callback =
            GNOMEPrompterCallback::new(window_id, self.service.clone(), self.path.clone())
                .await
                .map_err(|err| {
                    custom_service_error(&format!("Failed to create GNOMEPrompterCallback {err}."))
                })?;

        let path = OwnedObjectPath::from(callback.path().clone());

        let _ = self.gnome_callback.set(callback.clone());
        self.service.object_server().at(&path, callback).await?;
        tracing::debug!("Prompt `{}` created.", self.path);

        let prompter = GNOMEPrompterProxy::new(self.service.connection()).await?;
        tokio::spawn(async move { prompter.begin_prompting(&path).await });

        Ok(())
    }

    async fn prompt_cli(&self) -> Result<(), ServiceError> {
        let proxy = CliPrompterProxy::new(self.service.connection())
            .await
            .map_err(|e| custom_service_error(&format!("CLI prompter not available: {e}")))?;

        let label = &self.label;
        let description = match self.role {
            PromptRole::Unlock => formatx!(
                gettext("An application wants access to the keyring “{}”, but it is locked"),
                label,
            )
            .expect("Wrong format in translatable string"),
            PromptRole::CreateCollection => formatx!(
                gettext("An application wants to create a new keyring called “{}”. Choose the password you want to use for it."),
                label,
            )
            .expect("Wrong format in translatable string"),
            PromptRole::ChangePassword => formatx!(
                gettext("An application wants to change the password for the “{}” keyring. Choose the new password you want to use for it."),
                label,
            )
            .expect("Wrong format in translatable string"),
            PromptRole::Access => {
                return Err(custom_service_error(
                    "Access prompts need the socket prompter.",
                ));
            }
        };

        match proxy.prompt(&self.label, &description).await {
            Ok((fd, true)) => {
                let std_stream = std::os::unix::net::UnixStream::from(
                    fd.as_fd().try_clone_to_owned().expect("Failed to clone fd"),
                );
                std_stream.set_nonblocking(true).map_err(|e| {
                    custom_service_error(&format!("Failed to set non-blocking: {e}"))
                })?;
                let mut stream = tokio::net::UnixStream::from_std(std_stream)
                    .expect("Failed to create Tokio UnixStream");
                let mut buffer = String::new();
                stream.read_to_string(&mut buffer).await.map_err(|e| {
                    custom_service_error(&format!("Failed to read secret from CLI prompter: {e}"))
                })?;
                let secret = if buffer.is_empty() {
                    None
                } else {
                    Some(Secret::from(buffer))
                };

                match self.role {
                    PromptRole::Unlock => {
                        self.on_unlock_collection(secret).await?;
                    }
                    PromptRole::CreateCollection => {
                        self.on_create_collection(secret).await?;
                    }
                    PromptRole::ChangePassword => {
                        self.on_change_password(secret).await?;
                    }
                    PromptRole::Access => unreachable!("refused before asking"),
                }
                Ok(())
            }
            Ok((_, false)) => {
                tracing::info!("CLI prompter dismissed by user.");
                Err(custom_service_error("Prompt dismissed by user."))
            }
            Err(e) => Err(custom_service_error(&format!("CLI prompter failed: {e}"))),
        }
    }
    /// `Prompt` with the socket prompter: connect, then run the conversation in
    /// a task that `Dismiss` can abort.
    async fn start_socket_prompt(&self) -> Result<(), ServiceError> {
        if self.socket_started.swap(true, Ordering::SeqCst) {
            return Err(custom_service_error(
                "A prompt callback is ongoing already.",
            ));
        }

        let socket = self.service.prompter_socket().unwrap();
        let caller = self.service.caller(self.client.as_ref()).await;
        let session = socket_prompter::Session::connect(&socket, caller)
            .await
            .map_err(|err| {
                custom_service_error(&format!(
                    "Failed to reach the prompter at {}: {err}.",
                    socket.display()
                ))
            })?;
        tracing::debug!("Prompt `{}` sent to the socket prompter.", self.path);

        let prompt = self.clone();
        let task = tokio::spawn(async move { prompt.run_socket_prompt(session).await });
        *self.socket_task.lock().unwrap() = Some(task.abort_handle());
        Ok(())
    }

    async fn run_socket_prompt(self, mut session: socket_prompter::Session) {
        let (dismissed, result) = match self.socket_conversation(&mut session).await {
            Ok(Some(result)) => (false, result),
            Ok(None) => {
                tracing::debug!("Prompt `{}` dismissed.", self.path);
                (true, (self.dismissed_result)())
            }
            Err(err) => {
                tracing::error!("Prompt `{}` failed: {err}", self.path);
                (true, (self.dismissed_result)())
            }
        };
        // The prompter sees EOF now, before the client hears back.
        drop(session);

        if let Ok(signal_emitter) = self.service.signal_emitter(self.path.clone()) {
            let _ = Prompt::completed(&signal_emitter, dismissed, result).await;
        }
        let _ = self
            .service
            .object_server()
            .remove::<Self, _>(&self.path)
            .await;
        self.service.remove_prompt(&self.path).await;
    }

    /// The keyring's password if the role needs one, then the access step if
    /// any, then the action. `None` when the prompter refused at any step.
    ///
    /// A password given for a read also allows the client (igptr, 2026-10-06:
    /// typing it is consent, as long as the dialog names the app, which the
    /// request's caller and pidfd let it do); a delete is still asked for.
    async fn socket_conversation(
        &self,
        session: &mut socket_prompter::Session,
    ) -> Result<Option<OwnedValue>, ServiceError> {
        let prompt_path = self.path.as_str();
        let read_step = match (&self.access, &self.client) {
            (Some(step), Some(client)) if step.operation == Operation::Read => Some((step, client)),
            _ => None,
        };

        let secret = match self.role {
            PromptRole::Unlock | PromptRole::CreateCollection => {
                match ask_password(
                    session,
                    self.role,
                    &self.label,
                    Some(prompt_path),
                    self.collection(),
                    read_step.map(|_| Operation::Read),
                )
                .await?
                {
                    Some(secret) => {
                        if let Some((step, client)) = read_step {
                            let objects = self.service.needs_access(client, step).await;
                            self.service.grant_access(client, &objects).await;
                        }
                        Some(secret)
                    }
                    None => return Ok(None),
                }
            }
            PromptRole::ChangePassword => {
                return Err(custom_service_error(
                    "Changing a keyring's password is not supported by the socket prompter.",
                ));
            }
            PromptRole::Access => None,
        };

        if let (Some(step), Some(client)) = (&self.access, &self.client) {
            let objects = self.service.needs_access(client, step).await;
            if !objects.is_empty() {
                let labels = self.service.labels_of(&objects).await;
                let request =
                    Request::access(&self.label, Some(prompt_path), step.operation, &labels);
                match session.ask(&request).await.map_err(prompter_error)? {
                    Reply::Allow => {
                        if step.operation == Operation::Read {
                            self.service.grant_access(client, &objects).await;
                        }
                    }
                    _ => return Ok(None),
                }
            }
        }

        let Some(action) = self.take_action().await else {
            return Err(custom_service_error(
                "Prompt action was already executed or not set",
            ));
        };
        action.execute(secret).await.map(Some)
    }
}

/// Ask the socket prompter for a keyring's password until it gives one that
/// works, and unlock `collection` with it. For an existing keyring the
/// password must open it; for a new one (`CreateCollection`) it must not be
/// empty, and it becomes the keyring's password. `None` when refused.
pub(crate) async fn ask_password(
    session: &mut socket_prompter::Session,
    role: PromptRole,
    label: &str,
    prompt_path: Option<&str>,
    collection: Option<&Collection>,
    allows: Option<Operation>,
) -> Result<Option<Secret>, ServiceError> {
    let type_ = match role {
        PromptRole::Unlock => RequestType::Unlock,
        PromptRole::CreateCollection => RequestType::Create,
        PromptRole::ChangePassword | PromptRole::Access => {
            unreachable!("only unlock and create prompts ask for a password")
        }
    };
    let incorrect = gettext("The unlock password was incorrect");
    let empty = gettext("The password cannot be empty");
    let mut request = Request::password(type_, label, prompt_path);
    request.operation = allows;

    loop {
        let secret = match session.ask(&request).await.map_err(prompter_error)? {
            Reply::Password(secret) => secret,
            _ => return Ok(None),
        };

        let accepted = match (role, collection) {
            (PromptRole::Unlock, Some(collection)) => {
                is_valid_secret(collection, label, &secret).await?
            }
            (PromptRole::Unlock, None) => {
                return Err(custom_service_error("Unlock requires a collection"));
            }
            _ => !secret.is_empty(),
        };
        if !accepted {
            tracing::error!("Keyring {label} not unlocked: the password was refused.");
            request.warning = Some(if role == PromptRole::Unlock {
                &incorrect
            } else {
                &empty
            });
            continue;
        }

        if let Some(collection) = collection {
            collection.set_locked(false, Some(secret.clone())).await?;
        }
        return Ok(Some(secret));
    }
}

async fn is_valid_secret(
    collection: &Collection,
    label: &str,
    secret: &Secret,
) -> Result<bool, ServiceError> {
    let keyring_guard = collection.keyring.read().await;
    keyring_guard
        .as_ref()
        .unwrap()
        .validate_secret(secret)
        .await
        .map_err(|err| {
            custom_service_error(&format!(
                "Failed to validate secret for {label} keyring: {err}."
            ))
        })
}

fn prompter_error(err: std::io::Error) -> ServiceError {
    custom_service_error(&format!("Failed to talk to the prompter: {err}."))
}

/// What a dismissed prompt completes with.
fn empty_result() -> OwnedValue {
    Value::new::<Vec<OwnedObjectPath>>(vec![])
        .try_into_owned()
        .unwrap()
}

fn no_path_result() -> OwnedValue {
    Value::new(OwnedObjectPath::default())
        .try_into_owned()
        .unwrap()
}

#[cfg(test)]
mod tests;
