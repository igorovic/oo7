// org.freedesktop.Secret.Item

use std::{collections::HashMap, sync::Arc};

use oo7::dbus::{ServiceError, api::DBusSecretInner};
use tokio::sync::Mutex;
use zbus::{
    message::Header,
    zvariant::{ObjectPath, OwnedObjectPath},
};

use crate::{
    Service,
    collection::Collection,
    error::custom_service_error,
    prompt::{AccessStep, PromptRole},
    service::client_of,
    socket_prompter::Operation,
};

#[derive(Clone)]
pub struct Item {
    // Properties
    pub(super) inner: Arc<Mutex<Option<oo7::file::Item>>>,
    // Other attributes
    service: Service,
    collection_path: OwnedObjectPath,
    path: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("Prompt"))]
    pub async fn delete(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let caller = if let Some(sender) = header.sender() {
            self.service.peer_display_name(sender).await
        } else {
            "unknown".to_string()
        };
        let Some(collection) = self
            .service
            .collection_from_path(&self.collection_path)
            .await
        else {
            return Err(ServiceError::NoSuchObject(format!(
                "Collection `{}` does not exist.",
                self.collection_path
            )));
        };

        // With per-client access, deleting always asks, even a client allowed
        // to read the item.
        let ask_access = self.service.per_client_access();
        let locked = self.is_locked().await || collection.is_locked().await;
        // Check if item or collection is locked
        if locked || ask_access {
            // Create a prompt to unlock and delete the item
            let role = if locked {
                PromptRole::Unlock
            } else {
                PromptRole::Access
            };
            let mut prompt = crate::prompt::Prompt::new(
                self.service.clone(),
                role,
                collection.label().await,
                Some(collection.clone()),
            )
            .await;
            if ask_access {
                let Some(client) = client_of(&header) else {
                    return Err(custom_service_error("The client has no bus name."));
                };
                prompt = prompt.with_client(client).with_access(AccessStep {
                    operation: Operation::Delete,
                    objects: vec![self.path.clone()],
                });
            }
            let prompt_path = OwnedObjectPath::from(prompt.path().clone());

            let item_self = self.clone();
            let coll = collection.clone();
            let caller = caller.to_owned();
            let action = crate::prompt::PromptAction::new(
                move |unlock_secret: Option<oo7::Secret>| async move {
                    // Unlock the collection
                    coll.set_locked(false, unlock_secret).await?;

                    // Now delete the item
                    item_self.delete_unlocked(&coll, &caller).await?;

                    Ok(zbus::zvariant::Value::new(OwnedObjectPath::default())
                        .try_into_owned()
                        .unwrap())
                },
            );

            prompt.set_action(action).await;

            // Register the prompt
            self.service
                .register_prompt(prompt_path.clone(), prompt.clone())
                .await;

            self.service
                .object_server()
                .at(&prompt_path, prompt)
                .await?;

            tracing::debug!(
                "Delete prompt created at `{}` for locked item `{}`",
                prompt_path,
                self.path
            );

            return Ok(prompt_path);
        }

        // Item and collection are unlocked, proceed directly
        self.delete_unlocked(&collection, &caller).await?;
        Ok(OwnedObjectPath::default())
    }

    #[zbus(out_args("secret"))]
    pub async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(DBusSecretInner,), ServiceError> {
        self.check_access(&header).await?;
        self.secret(session).await
    }

    pub async fn set_secret(
        &self,
        secret: DBusSecretInner,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), ServiceError> {
        self.check_access(&header).await?;
        let DBusSecretInner(ref session, ref iv, ref secret, ref content_type) = secret;

        let Some(session) = self.service.session(session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        {
            let mut inner = self.inner.lock().await;
            let inner = inner.as_mut().unwrap();
            if inner.is_locked() {
                tracing::error!("Cannot set secret of a locked object `{}`", self.path);
                return Err(ServiceError::IsLocked(format!(
                    "Cannot set secret of a locked object `{}`.",
                    self.path
                )));
            }

            match session.aes_key() {
                Some(key) => {
                    let decrypted = oo7::crypto::decrypt(secret, &key, iv).map_err(|err| {
                        custom_service_error(&format!("Failed to decrypt secret {err}."))
                    })?;
                    inner.as_mut_unlocked().set_secret(decrypted);
                }
                None => {
                    inner.as_mut_unlocked().set_secret(secret);
                }
            }

            // Ensure content-type attribute is stored
            let mut attributes = inner.as_unlocked().attributes().clone();
            if !attributes.contains_key(oo7::CONTENT_TYPE_ATTRIBUTE) {
                attributes.insert(
                    oo7::CONTENT_TYPE_ATTRIBUTE.to_owned(),
                    content_type.as_str().into(),
                );
            } else {
                attributes
                    .entry(oo7::CONTENT_TYPE_ATTRIBUTE.to_string())
                    .and_modify(|v| *v = content_type.as_str().into());
            }
            inner.as_mut_unlocked().set_attributes(&attributes);
        }

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        if let Ok(signal_emitter) = self.service.signal_emitter(&self.path)
            && let Err(err) = self.modified_changed(&signal_emitter).await
        {
            tracing::error!(
                "Failed to emit PropertiesChanged signal for Modified: {}",
                err
            );
        }

        tracing::debug!("Secret updated for item: {}.", self.path);

        Ok(())
    }

    /// Locked with its keyring, and with per-client access, for a client not
    /// allowed to use it yet. Its label and attributes stay readable while the
    /// keyring is unlocked, as KeePassXC does: clients load them before asking
    /// to unlock.
    #[zbus(property, name = "Locked")]
    pub async fn locked(&self, #[zbus(header)] header: Option<Header<'_>>) -> bool {
        if self.is_locked().await {
            return true;
        }
        match header {
            Some(header) => {
                !self
                    .service
                    .may_access(client_of(&header).as_ref(), &self.path)
                    .await
            }
            // A signal: the state every allowed client sees.
            None => false,
        }
    }

    #[zbus(property, name = "Attributes")]
    pub async fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        let inner = self.inner.lock().await;
        let inner = inner.as_ref().unwrap();
        if inner.is_locked() {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get attributes of a locked object `{}`.",
                self.path
            )));
        }

        Ok(inner
            .as_unlocked()
            .attributes()
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_string()))
            .collect())
    }

    #[zbus(property, name = "Attributes")]
    pub async fn set_attributes(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: Option<Header<'_>>,
    ) -> Result<(), zbus::Error> {
        if let Some(header) = &header {
            self.check_access(header).await.map_err(|err| {
                zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string())))
            })?;
        }
        {
            let mut inner = self.inner.lock().await;
            let inner = inner.as_mut().unwrap();
            if inner.is_locked() {
                tracing::error!("Cannot set attributes of a locked object `{}`", self.path);
                return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                    format!("Cannot set attributes of a locked object `{}`.", self.path),
                ))));
            }
            inner.as_mut_unlocked().set_attributes(&attributes);
        }

        let signal_emitter = self
            .service
            .signal_emitter(&self.collection_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.attributes_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;

        tracing::debug!("Attributes updated for item `{}`.", self.path);
        Ok(())
    }

    #[zbus(property, name = "Label")]
    pub async fn label(&self) -> zbus::fdo::Result<String> {
        let inner = self.inner.lock().await;
        let inner = inner.as_ref().unwrap();
        if inner.is_locked() {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get label of a locked object `{}`.",
                self.path
            )));
        }

        Ok(inner.as_unlocked().label().to_owned())
    }

    #[zbus(property, name = "Label")]
    pub async fn set_label(
        &self,
        label: &str,
        #[zbus(header)] header: Option<Header<'_>>,
    ) -> Result<(), zbus::Error> {
        if let Some(header) = &header {
            self.check_access(header).await.map_err(|err| {
                zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string())))
            })?;
        }
        {
            let mut inner = self.inner.lock().await;
            let inner = inner.as_mut().unwrap();
            if inner.is_locked() {
                tracing::error!("Cannot set label of a locked object `{}`", self.path);
                return Err(zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(
                    format!("Cannot set label of a locked object `{}`.", self.path),
                ))));
            }
            inner.as_mut_unlocked().set_label(label);
        }

        let signal_emitter = self
            .service
            .signal_emitter(&self.collection_path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        let signal_emitter = self
            .service
            .signal_emitter(&self.path)
            .map_err(|err| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(err.to_string()))))?;
        self.label_changed(&signal_emitter).await?;
        self.modified_changed(&signal_emitter).await?;

        tracing::debug!("Label updated for item `{}`.", self.path);
        Ok(())
    }

    #[zbus(property, name = "Created")]
    pub async fn created_at(&self) -> zbus::fdo::Result<u64> {
        let inner = self.inner.lock().await;
        let inner = inner.as_ref().unwrap();
        if inner.is_locked() {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get created timestamp of a locked object `{}`.",
                self.path
            )));
        }
        Ok(inner.as_unlocked().created().as_secs())
    }

    #[zbus(property, name = "Modified")]
    pub async fn modified_at(&self) -> zbus::fdo::Result<u64> {
        let inner = self.inner.lock().await;
        let inner = inner.as_ref().unwrap();
        if inner.is_locked() {
            return Err(zbus::fdo::Error::Failed(format!(
                "Cannot get modified timestamp of a locked object `{}`.",
                self.path
            )));
        }
        Ok(inner.as_unlocked().modified().as_secs())
    }
}

impl Item {
    /// The secret, for whoever may read it: `GetSecret` once the access is checked.
    pub async fn secret(
        &self,
        session: OwnedObjectPath,
    ) -> Result<(DBusSecretInner,), ServiceError> {
        let Some(session) = self.service.session(&session).await else {
            tracing::error!("The session `{}` does not exist.", session);
            return Err(ServiceError::NoSession(format!(
                "The session `{session}` does not exist."
            )));
        };

        let inner = self.inner.lock().await;
        let inner = inner.as_ref().unwrap();
        if inner.is_locked() {
            tracing::error!("Cannot get secret of a locked object `{}`", self.path);
            return Err(ServiceError::IsLocked(format!(
                "Cannot get secret of a locked object `{}`.",
                self.path
            )));
        }
        let secret = inner.as_unlocked().secret();
        let content_type = secret.content_type();

        tracing::debug!("Secret retrieved from the item: {}.", self.path);

        match session.aes_key() {
            Some(key) => {
                let iv = oo7::crypto::generate_iv().map_err(|err| {
                    custom_service_error(&format!("Failed to generate iv {err}."))
                })?;
                let encrypted = oo7::crypto::encrypt(secret, &key, &iv).map_err(|err| {
                    custom_service_error(&format!("Failed to encrypt secret {err}."))
                })?;

                Ok((DBusSecretInner(
                    session.path().clone().into(),
                    iv,
                    encrypted,
                    content_type,
                ),))
            }
            None => Ok((DBusSecretInner(
                session.path().clone().into(),
                Vec::new(),
                secret.to_vec(),
                content_type,
            ),)),
        }
    }

    /// With per-client access, the sender may use this item only once allowed:
    /// until then it is locked for it.
    async fn check_access(&self, header: &Header<'_>) -> Result<(), ServiceError> {
        if self
            .service
            .may_access(client_of(header).as_ref(), &self.path)
            .await
        {
            return Ok(());
        }
        tracing::error!("The client may not use `{}`", self.path);
        Err(ServiceError::IsLocked(format!(
            "The object `{}` is locked for this client.",
            self.path
        )))
    }

    pub fn new(
        item: oo7::file::Item,
        service: Service,
        collection_path: OwnedObjectPath,
        path: OwnedObjectPath,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(item))),
            path,
            collection_path,
            service,
        }
    }

    pub fn path(&self) -> &ObjectPath<'_> {
        &self.path
    }

    /// Locked with its keyring, whoever asks.
    pub async fn is_locked(&self) -> bool {
        self.inner.lock().await.as_ref().unwrap().is_locked()
    }

    pub(crate) async fn set_locked(
        &self,
        locked: bool,
        keyring: &oo7::file::UnlockedKeyring,
    ) -> Result<(), ServiceError> {
        let mut inner_guard = self.inner.lock().await;

        if let Some(old_item) = inner_guard.take() {
            let new_item = match (old_item, locked) {
                (oo7::file::Item::Unlocked(unlocked), true) => {
                    let locked_item = keyring.lock_item(unlocked).await.map_err(|err| {
                        custom_service_error(&format!("Failed to lock item: {err}"))
                    })?;
                    oo7::file::Item::Locked(locked_item)
                }
                (oo7::file::Item::Locked(locked_item), false) => {
                    let unlocked = keyring.unlock_item(locked_item).await.map_err(|err| {
                        custom_service_error(&format!("Failed to unlock item: {err}"))
                    })?;
                    oo7::file::Item::Unlocked(unlocked)
                }
                (other, _) => other,
            };
            *inner_guard = Some(new_item);
        }

        drop(inner_guard);

        let signal_emitter = self.service.signal_emitter(&self.path)?;
        self.locked_changed(&signal_emitter).await?;

        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_changed(&signal_emitter, &self.path).await?;

        tracing::debug!(
            "Item: {} is {}.",
            self.path,
            if locked { "locked" } else { "unlocked" }
        );

        Ok(())
    }

    async fn delete_unlocked(
        &self,
        collection: &Collection,
        caller: &str,
    ) -> Result<(), ServiceError> {
        // Delete from keyring and collection's items list
        collection.delete_item(&self.path).await?;

        // Remove from object server
        self.service
            .object_server()
            .remove::<Item, _>(&self.path)
            .await?;

        // Emit ItemDeleted signal
        let signal_emitter = self.service.signal_emitter(&self.collection_path)?;
        Collection::item_deleted(&signal_emitter, &self.path).await?;

        tracing::info!("Item `{}` deleted by {caller}.", &self.path);

        Ok(())
    }
}

#[cfg(test)]
mod tests;
