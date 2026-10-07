// org.freedesktop.Secret.Service

use std::{
    collections::{HashMap, HashSet},
    os::fd::AsFd,
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU32, Ordering},
    },
};

use oo7::{
    Key, Secret,
    dbus::{
        Algorithm, ServiceError,
        api::{DBusSecretInner, Properties},
    },
    file::{Keyring, LockedKeyring, UnlockedKeyring},
};
use tokio::sync::{Mutex, watch};
use tokio_stream::StreamExt;
use zbus::{
    fdo::{RequestNameFlags, RequestNameReply},
    message::Header,
    names::{BusName, OwnedUniqueName, UniqueName},
    object_server::SignalEmitter,
    proxy::Defaults,
    zvariant::{ObjectPath, Optional, OwnedObjectPath, OwnedValue, Value},
};

#[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
pub use crate::gnome::internal::InternalInterface;
#[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
use crate::plasma::prompter::in_plasma_environment;
use crate::{
    collection::Collection,
    error::{Error, custom_service_error},
    item::Item,
    migration::{self, PendingMigration},
    prompt::{AccessStep, Prompt, PromptAction, PromptRole},
    session::{PeerInfo, Session, SessionType},
    socket_prompter::{self, Caller, Operation},
};

const DEFAULT_COLLECTION_ALIAS_PATH: ObjectPath<'static> =
    ObjectPath::from_static_str_unchecked("/org/freedesktop/secrets/aliases/default");

/// Prompter type
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PrompterType {
    #[allow(clippy::upper_case_acronyms)]
    GNOME,
    Plasma,
    Cli,
}

/// How the daemon was started, beyond what upstream oo7 does by default.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// Items are locked for each client until that client is allowed to use
    /// them through an access prompt; see [`Service::may_access`]. Needs the
    /// socket prompter, the only one that can ask for access.
    pub per_client_access: bool,
    /// Prompts go to the prompter listening on this unix socket instead of
    /// GNOME's or Plasma's; see [`crate::socket_prompter`].
    pub prompter_socket: Option<PathBuf>,
}

/// The unique bus name of the client that sent a message.
///
/// On a peer-to-peer connection there is no bus to set it, and tests use a
/// fixed one unless the message names its sender itself.
pub(crate) fn client_of(header: &Header<'_>) -> Option<OwnedUniqueName> {
    if let Some(sender) = header.sender() {
        return Some(sender.to_owned().into());
    }
    #[cfg(test)]
    {
        Some(UniqueName::try_from(":p2p.test").unwrap().into())
    }
    #[cfg(not(test))]
    {
        None
    }
}

#[derive(Clone)]
pub struct Service {
    // Properties
    pub(crate) collections: Arc<Mutex<HashMap<OwnedObjectPath, Collection>>>,
    // Other attributes
    connection: Arc<OnceLock<zbus::Connection>>,
    // sessions mapped to their corresponding object path on the bus
    sessions: Arc<Mutex<HashMap<OwnedObjectPath, Session>>>,
    session_index: Arc<AtomicU32>,
    // prompts mapped to their corresponding object path on the bus
    prompts: Arc<Mutex<HashMap<OwnedObjectPath, Prompt>>>,
    prompt_index: Arc<AtomicU32>,
    // pending collection creations: prompt_path -> (label, alias)
    pending_collections: Arc<Mutex<HashMap<OwnedObjectPath, (String, String)>>>,
    // pending keyring migrations: name -> migration
    pub(crate) pending_migrations: Arc<Mutex<HashMap<String, PendingMigration>>>,
    // Data directory for keyrings (e.g., ~/.local/share or test temp dir)
    data_dir: std::path::PathBuf,
    // PAM socket path (None for tests that don't need PAM listener)
    pub(crate) pam_socket: Option<std::path::PathBuf>,
    // Override for prompter type (mainly for tests)
    pub(crate) prompter_type_override: Arc<Mutex<Option<PrompterType>>>,
    options: Arc<std::sync::RwLock<Options>>,
    // items each client was allowed to use, by unique bus name; dropped when
    // the client leaves the bus
    access: Arc<Mutex<HashMap<OwnedUniqueName, HashSet<OwnedObjectPath>>>>,
    // keyrings being unlocked because a search found them locked: collection
    // path -> the outcome, `None` while the prompter is still asking
    #[allow(clippy::type_complexity)]
    search_unlocks: Arc<Mutex<HashMap<OwnedObjectPath, watch::Receiver<Option<bool>>>>>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    pub async fn open_session(
        &self,
        algorithm: Algorithm,
        input: Value<'_>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] object_server: &zbus::ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath), ServiceError> {
        let (public_key, aes_key) = match algorithm {
            Algorithm::Plain => (None, None),
            Algorithm::Encrypted => {
                let client_public_key = Key::try_from(input).map_err(|err| {
                    custom_service_error(&format!(
                        "Input Value could not be converted into a Key {err}."
                    ))
                })?;
                let private_key = Key::generate_private_key().map_err(|err| {
                    custom_service_error(&format!("Failed to generate private key {err}."))
                })?;
                (
                    Some(Key::generate_public_key(&private_key).map_err(|err| {
                        custom_service_error(&format!("Failed to generate public key {err}."))
                    })?),
                    Some(
                        Key::generate_aes_key(&private_key, &client_public_key).map_err(|err| {
                            custom_service_error(&format!("Failed to generate aes key {err}."))
                        })?,
                    ),
                )
            }
        };

        let sender = if let Some(s) = header.sender() {
            s.to_owned()
        } else {
            #[cfg(any(test, feature = "test-util"))]
            {
                // For p2p test connections, use a dummy sender since p2p
                // connections don't have a bus to assign unique
                // names
                UniqueName::try_from(":p2p.test").unwrap()
            }
            #[cfg(not(any(test, feature = "test-util")))]
            {
                return Err(custom_service_error("Failed to get sender from header."));
            }
        };

        let peer_info = async {
            let proxy = zbus::fdo::DBusProxy::new(self.connection()).await.ok()?;
            let pid = proxy
                .get_connection_unix_process_id(sender.as_ref().into())
                .await
                .ok()?;
            let cmdline = tokio::fs::read(format!("/proc/{pid}/cmdline")).await.ok()?;
            let name = cmdline.split(|&b| b == 0).next()?;
            let name = std::path::Path::new(std::str::from_utf8(name).ok()?)
                .file_name()?
                .to_str()?
                .to_owned();
            let session_type = SessionType::detect(pid).await;
            Some(PeerInfo::new(pid, name, session_type))
        }
        .await;
        let session = Session::new(
            aes_key.map(Arc::new),
            self.clone(),
            sender.clone(),
            peer_info,
        )
        .await;
        let path = OwnedObjectPath::from(session.path().clone());

        match session.peer_info() {
            Some(info) => {
                tracing::info!("Client {} ({}) connected, session: {}", sender, info, path)
            }
            None => tracing::info!("Client {} connected, session: {}", sender, path),
        }

        self.sessions
            .lock()
            .await
            .insert(path.clone(), session.clone());

        object_server.at(&path, session).await?;

        let service_key = public_key
            .map(OwnedValue::from)
            .unwrap_or_else(|| Value::new::<Vec<u8>>(vec![]).try_into_owned().unwrap());

        Ok((service_key, path))
    }

    #[zbus(out_args("collection", "prompt"))]
    pub async fn create_collection(
        &self,
        properties: Properties,
        alias: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(OwnedObjectPath, ObjectPath<'_>), ServiceError> {
        let label = properties.label().to_owned();
        let alias = alias.to_owned();

        // Create a prompt to get the password for the new collection
        let mut prompt = Prompt::new(
            self.clone(),
            PromptRole::CreateCollection,
            label.clone(),
            None,
        )
        .await;
        // Only to name the caller to the socket prompter.
        if let Some(client) = client_of(&header) {
            prompt = prompt.with_client(client);
        }
        let prompt = prompt.with_path_result();
        let prompt_path = OwnedObjectPath::from(prompt.path().clone());

        // Store the collection metadata for later creation
        self.pending_collections
            .lock()
            .await
            .insert(prompt_path.clone(), (label, alias));

        // Create the collection creation action
        let service = self.clone();
        let creation_prompt_path = prompt_path.clone();
        let action = PromptAction::new(move |secret: Option<Secret>| async move {
            let collection_path = service
                .complete_collection_creation(&creation_prompt_path, secret)
                .await?;

            Ok(Value::new(collection_path).try_into_owned().unwrap())
        });

        prompt.set_action(action).await;

        // Register the prompt
        self.prompts
            .lock()
            .await
            .insert(prompt_path.clone(), prompt.clone());

        self.object_server().at(&prompt_path, prompt).await?;

        tracing::debug!("CreateCollection prompt created at `{}`", prompt_path);

        // Return empty collection path and the prompt path
        Ok((OwnedObjectPath::default(), prompt_path.into()))
    }

    #[zbus(out_args("unlocked", "locked"))]
    pub async fn search_items(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let client = client_of(&header);
        self.unlock_keyrings_for_search(client.as_ref()).await?;

        let mut unlocked = Vec::new();
        let mut locked = Vec::new();
        let collections = self.collections.lock().await;

        for collection in collections.values() {
            let items = collection.search_inner_items(&attributes).await?;
            for item in items {
                if item.is_locked().await || !self.may_access(client.as_ref(), item.path()).await {
                    locked.push(item.path().clone().into());
                } else {
                    unlocked.push(item.path().clone().into());
                }
            }
        }

        if unlocked.is_empty() && locked.is_empty() {
            tracing::debug!(
                "Items with attributes {:?} does not exist in any collection.",
                attributes
            );
        } else {
            tracing::debug!("Items with attributes {:?} found.", attributes);
        }

        Ok((unlocked, locked))
    }

    #[zbus(out_args("unlocked", "prompt"))]
    pub async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        self.unlock_for(client_of(&header), objects).await
    }

    #[zbus(out_args("locked", "Prompt"))]
    pub async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        tracing::info!("Lock requested for {} objects.", objects.len());
        let (locked, not_locked) = self.set_locked(true, &objects).await?;
        // Locking never requires prompts, so not_locked should always be empty
        debug_assert!(
            not_locked.is_empty(),
            "Lock operation should never require prompts"
        );
        Ok((locked, OwnedObjectPath::default()))
    }

    #[zbus(out_args("secrets"))]
    pub async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, DBusSecretInner>, ServiceError> {
        tracing::debug!(
            "GetSecrets called for {} items with session {}.",
            items.len(),
            session
        );
        let client = client_of(&header);
        let mut secrets = HashMap::new();
        let collections = self.collections.lock().await;

        'outer: for collection in collections.values() {
            for item in &items {
                if let Some(item) = collection.item_from_path(item).await {
                    // Not allowed for this client: as if it were locked.
                    if !self.may_access(client.as_ref(), item.path()).await {
                        continue;
                    }
                    match item.secret(session.clone()).await {
                        Ok((secret,)) => {
                            secrets.insert(item.path().clone().into(), secret);
                            // To avoid iterating through all the remaining
                            // collections, if the
                            // items secrets are already retrieved.
                            if secrets.len() == items.len() {
                                break 'outer;
                            }
                        }
                        // Avoid erroring out if an item is locked.
                        Err(ServiceError::IsLocked(_)) => {
                            continue;
                        }
                        Err(err) => {
                            return Err(err);
                        }
                    };
                }
            }
        }

        tracing::debug!(
            "GetSecrets returned {} of {} requested secrets.",
            secrets.len(),
            items.len()
        );
        Ok(secrets)
    }

    #[zbus(out_args("collection"))]
    pub async fn read_alias(&self, name: &str) -> Result<OwnedObjectPath, ServiceError> {
        // Map "login" alias to "default" for compatibility with gnome-keyring
        let alias_to_find = if name == Self::LOGIN_ALIAS {
            oo7::dbus::Service::DEFAULT_COLLECTION
        } else {
            name
        };

        let collections = self.collections.lock().await;

        for (path, collection) in collections.iter() {
            if collection.alias().await == alias_to_find {
                tracing::debug!("Collection: {} found for alias: {}.", path, name);
                return Ok(path.to_owned());
            }
        }

        tracing::info!("Collection with alias {} does not exist.", name);

        Ok(OwnedObjectPath::default())
    }

    pub async fn set_alias(
        &self,
        name: &str,
        collection: OwnedObjectPath,
    ) -> Result<(), ServiceError> {
        let collections = self.collections.lock().await;

        for (path, other_collection) in collections.iter() {
            if *path == collection {
                other_collection.set_alias(name).await;

                tracing::info!("Collection: {} alias updated to {}.", collection, name);
                return Ok(());
            }
        }

        tracing::info!("Collection: {} does not exist.", collection);

        Err(ServiceError::NoSuchObject(format!(
            "The collection: {collection} does not exist.",
        )))
    }

    #[zbus(property, name = "Collections")]
    pub async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.collections.lock().await.keys().cloned().collect()
    }

    #[zbus(signal, name = "CollectionCreated")]
    pub async fn collection_created(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionDeleted")]
    pub async fn collection_deleted(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal, name = "CollectionChanged")]
    pub async fn collection_changed(
        signal_emitter: &SignalEmitter<'_>,
        collection: &ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

impl Service {
    const LOGIN_ALIAS: &str = "login";

    /// Set the prompter type override
    #[allow(unused)]
    pub(crate) async fn set_prompter_type(&self, prompter_type: PrompterType) {
        *self.prompter_type_override.lock().await = Some(prompter_type);
    }

    /// Get the prompter type to use based on the caller's session type
    pub(crate) async fn prompter_type(&self, peer_info: Option<&PeerInfo>) -> PrompterType {
        if let Some(override_type) = self.prompter_type_override.lock().await.as_ref() {
            return *override_type;
        }

        let is_graphical = peer_info
            .map(|p| p.session_type().is_graphical())
            .unwrap_or_default();

        if is_graphical {
            #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
            {
                if in_plasma_environment(self.connection()).await {
                    return PrompterType::Plasma;
                }
            }

            return PrompterType::GNOME;
        }

        PrompterType::Cli
    }

    pub(crate) fn new(
        data_dir: std::path::PathBuf,
        pam_socket: Option<std::path::PathBuf>,
    ) -> Self {
        Self {
            collections: Arc::new(Mutex::new(HashMap::new())),
            connection: Arc::new(OnceLock::new()),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_index: Arc::new(AtomicU32::new(0)),
            prompts: Arc::new(Mutex::new(HashMap::new())),
            prompt_index: Arc::new(AtomicU32::new(0)),
            pending_collections: Arc::new(Mutex::new(HashMap::new())),
            pending_migrations: Arc::new(Mutex::new(HashMap::new())),
            data_dir,
            pam_socket,
            prompter_type_override: Arc::new(Mutex::new(None)),
            options: Default::default(),
            access: Default::default(),
            search_unlocks: Default::default(),
        }
    }

    pub async fn run(
        secret: Option<Secret>,
        request_replacement: bool,
        options: Options,
    ) -> Result<zbus::Connection, Error> {
        // Compute data directory from environment variables
        let data_dir = std::env::var_os("XDG_DATA_HOME")
            .filter(|h| !h.is_empty())
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|h| !h.is_empty())
                    .map(std::path::PathBuf::from)
                    .map(|p| p.join(".local/share"))
            })
            .ok_or_else(|| {
                Error::IO(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No data directory found (XDG_DATA_HOME or HOME)",
                ))
            })?;

        // Compute PAM socket path from environment variable
        let pam_socket = std::env::var_os("OO7_PAM_SOCKET").map(std::path::PathBuf::from);

        let service = Self::new(data_dir, pam_socket);
        service.set_options(options);

        // Start PAM listener early so it can buffer secrets arriving before
        // D-Bus is ready (e.g. during PAM-initiated login startup).
        tracing::info!("Starting PAM listener");
        let pam_listener = crate::pam_listener::PamListener::new(service.clone());
        let pam_listener_replay = pam_listener.clone();
        tokio::spawn(async move {
            if let Err(e) = pam_listener.start().await {
                tracing::error!("PAM listener error: {}", e);
            }
        });

        // The name is requested only once the service is initialized, below: a
        // call between owning it and `initialize` setting the connection
        // panicked in `Service::connection`, and its client never got an answer.
        let connection = zbus::connection::Builder::session()?
            .serve_at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )?
            .build()
            .await?;

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                InternalInterface::new(service.clone()),
            )
            .await?;

        // Discover existing keyrings
        let discovered_keyrings = service.discover_keyrings(secret.clone()).await?;

        let connection_clone = connection.clone();
        service
            .initialize(connection, discovered_keyrings, secret, true)
            .await?;

        // The flags `Builder::name` used: replaceable, replacing only when asked,
        // never queued.
        let mut flags = RequestNameFlags::AllowReplacement | RequestNameFlags::DoNotQueue;
        if request_replacement {
            flags |= RequestNameFlags::ReplaceExisting;
        }
        match connection_clone
            .request_name_with_flags(oo7::dbus::api::Service::DESTINATION.as_deref().unwrap(), flags)
            .await?
        {
            RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner => {}
            RequestNameReply::Exists | RequestNameReply::InQueue => {
                return Err(Error::Zbus(zbus::Error::NameTaken));
            }
        }

        // Replay any secrets that the PAM listener buffered during startup
        pam_listener_replay.replay_buffered_secrets().await;

        Ok(connection_clone)
    }

    #[cfg(any(test, feature = "test-util"))]
    #[allow(dead_code)]
    pub async fn run_with_connection(
        connection: zbus::Connection,
        data_dir: std::path::PathBuf,
        pam_socket: Option<std::path::PathBuf>,
        secret: Option<Secret>,
    ) -> Result<Self, Error> {
        let service = Self::new(data_dir, pam_socket);

        // Serve the service at the standard path
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                service.clone(),
            )
            .await?;

        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        connection
            .object_server()
            .at(
                oo7::dbus::api::Service::PATH.as_deref().unwrap(),
                InternalInterface::new(service.clone()),
            )
            .await?;

        let default_keyring = if let Some(secret) = secret.clone() {
            vec![(
                "default".to_owned(),
                "Login".to_owned(),
                oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                Keyring::Unlocked(UnlockedKeyring::temporary(secret).await?),
            )]
        } else {
            vec![]
        };

        service
            .initialize(connection, default_keyring, secret, false)
            .await?;
        Ok(service)
    }

    /// Generate a unique label and alias by checking registered
    /// collections and appending a counter if needed. Returns a tuple of
    /// (label, alias).
    fn make_unique_label_and_alias(
        collections: &HashMap<OwnedObjectPath, Collection>,
        label: &str,
        alias: &str,
    ) -> (String, String) {
        // Sanitize the label to create the path (for checking uniqueness)
        let base_path = crate::collection::collection_path(label)
            .expect("Sanitized label should always produce valid object path");
        if !collections.contains_key(&base_path) {
            return (label.to_owned(), alias.to_owned());
        }

        // Append counter until we find a unique one
        let mut counter = 2;
        loop {
            let path = crate::collection::collection_path(&format!("{label}{counter}"))
                .expect("Sanitized label should always produce valid object path");
            let new_label = format!("{}{}", label, counter);
            let new_alias = format!("{}{}", alias, counter);

            if !collections.contains_key(&path) {
                return (new_label, new_alias);
            }
            counter += 1;
        }
    }

    /// Discover existing keyrings in the data directory
    /// Returns a vector of (name, label, alias, keyring) tuples
    pub(crate) async fn discover_keyrings(
        &self,
        secret: Option<Secret>,
    ) -> Result<Vec<(String, String, String, Keyring)>, Error> {
        let mut discovered = Vec::new();

        let keyrings_dir = self.data_dir.join("keyrings");

        // Scan for v1 keyrings first
        let v1_dir = keyrings_dir.join("v1");
        if v1_dir.exists() {
            tracing::debug!("Scanning for v1 keyrings in {}", v1_dir.display());
            if let Ok(mut entries) = tokio::fs::read_dir(&v1_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    // Skip directories and non-.keyring files
                    if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                        continue;
                    }

                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        tracing::debug!("Found v1 keyring: {name}");

                        // Try to load the keyring
                        match self.load_keyring(&path, name, secret.as_ref()).await {
                            Ok((name, label, alias, keyring)) => {
                                discovered.push((name, label, alias, keyring))
                            }
                            Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        // Scan for v0 keyrings
        if keyrings_dir.exists() {
            tracing::debug!("Scanning for v0 keyrings in {}", keyrings_dir.display());
            if let Ok(mut entries) = tokio::fs::read_dir(&keyrings_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();

                    // Skip directories and non-.keyring files
                    if path.is_dir() || path.extension() != Some(std::ffi::OsStr::new("keyring")) {
                        continue;
                    }

                    if migration::stamp_path(&path).exists() {
                        continue;
                    }

                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        tracing::debug!("Found v0 keyring: {name}");

                        // Try to load the keyring
                        match self.load_keyring(&path, name, secret.as_ref()).await {
                            Ok((name, label, alias, keyring)) => {
                                discovered.push((name, label, alias, keyring))
                            }
                            Err(e) => tracing::warn!("Failed to load keyring {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        // Discover KWallet keyrings for migration
        #[cfg(feature = "kwallet_migration")]
        self.discover_kwallet_keyrings(&self.data_dir, secret.as_ref(), &mut discovered)
            .await;

        let pending_count = self.pending_migrations.lock().await.len();

        if discovered.is_empty() && pending_count == 0 {
            tracing::info!("No keyrings discovered in data directory");
        } else {
            tracing::info!(
                "Discovered {} keyring(s), {pending_count} pending migration(s)",
                discovered.len(),
            );
        }

        Ok(discovered)
    }

    /// Discover KWallet keyrings for migration
    #[cfg(feature = "kwallet_migration")]
    async fn discover_kwallet_keyrings(
        &self,
        data_dir: &std::path::Path,
        secret: Option<&Secret>,
        discovered: &mut Vec<(String, String, String, Keyring)>,
    ) {
        let kwallet_dir = data_dir.join("kwalletd");

        if !kwallet_dir.exists() {
            tracing::debug!("No kwalletd directory found, skipping KWallet discovery");
            return;
        }

        tracing::debug!("Scanning for KWallet files in {}", kwallet_dir.display());

        let Ok(mut entries) = tokio::fs::read_dir(&kwallet_dir).await else {
            tracing::warn!("Failed to read kwalletd directory");
            return;
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();

            // Only process .kwl files
            if path.extension().is_none_or(|ext| ext != "kwl") {
                continue;
            }

            if migration::stamp_path(&path).exists() {
                continue;
            }

            let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            tracing::debug!("Found KWallet file: {name}");

            // Use lowercased name as alias
            let alias = name.to_lowercase();

            let label = {
                let mut chars = name.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            };

            let migration = PendingMigration::KWallet {
                name: name.to_owned(),
                path: path.clone(),
                label: label.clone(),
                alias: alias.clone(),
            };

            if let Some(secret) = secret {
                tracing::debug!("Attempting immediate migration of KWallet keyring '{name}'",);
                match migration.migrate(&self.data_dir, Some(secret)).await {
                    Ok(unlocked) => {
                        tracing::info!("Successfully migrated KWallet keyring '{name}' to oo7",);
                        discovered.push((
                            name.to_owned(),
                            label,
                            alias,
                            Keyring::Unlocked(unlocked),
                        ));
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to migrate KWallet keyring '{name}' at {}: {e}. Creating locked placeholder collection.",
                            migration.path().display()
                        );
                    }
                }
            }

            // Migration failed or no secret - create locked placeholder and
            // register for pending migration
            tracing::debug!(
                "Creating locked placeholder for KWallet keyring '{name}', will migrate on unlock",
            );

            match LockedKeyring::open_at(&self.data_dir, name).await {
                Ok(locked) => {
                    tracing::debug!(
                        "Created locked placeholder for '{name}', adding to pending migrations",
                    );
                    discovered.push((
                        name.to_owned(),
                        label.clone(),
                        alias.clone(),
                        Keyring::Locked(locked),
                    ));
                    self.pending_migrations
                        .lock()
                        .await
                        .insert(name.to_owned(), migration);
                }
                Err(e) => {
                    tracing::error!("Failed to create placeholder keyring for '{name}': {e}");
                }
            }
        }
    }

    /// Load a single keyring from a file path
    /// Returns (name, label, alias, keyring)
    async fn load_keyring(
        &self,
        path: &std::path::Path,
        name: &str,
        secret: Option<&Secret>,
    ) -> Result<(String, String, String, Keyring), Error> {
        let alias = if name.eq_ignore_ascii_case(Self::LOGIN_ALIAS) {
            oo7::dbus::Service::DEFAULT_COLLECTION.to_owned()
        } else {
            name.to_owned().to_lowercase()
        };

        // Use name as label (capitalized for consistency with Login)
        let label = {
            let mut chars = name.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        };

        // Try to load the keyring
        let keyring = match LockedKeyring::load(path).await {
            Ok(locked_keyring) => {
                // Successfully loaded as v1 keyring
                if let Some(secret) = secret {
                    match locked_keyring.unlock(secret.clone()).await {
                        Ok(unlocked) => {
                            tracing::info!("Unlocked keyring '{}' from {:?}", name, path);
                            Keyring::Unlocked(unlocked)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to unlock keyring '{}' with provided secret: {}. Keeping it locked.",
                                name,
                                e
                            );
                            // Reload as locked since unlock consumed it
                            Keyring::Locked(LockedKeyring::load(path).await?)
                        }
                    }
                } else {
                    tracing::debug!("No secret provided, keeping keyring '{}' locked", name);
                    Keyring::Locked(locked_keyring)
                }
            }
            Err(oo7::file::Error::VersionMismatch(Some(version)))
                if version.first() == Some(&0) =>
            // v0 is the legacy version
            {
                // This is a v0 keyring that needs migration
                tracing::info!(
                    "Found legacy v0 keyring '{name}' at {}, registering for migration",
                    path.display()
                );

                let migration = PendingMigration::V0 {
                    name: name.to_owned(),
                    path: path.to_path_buf(),
                    label: label.clone(),
                    alias: alias.clone(),
                };

                tracing::debug!("Attempting immediate migration of v0 keyring '{name}'",);
                match migration.migrate(&self.data_dir, secret).await {
                    Ok(unlocked) => {
                        tracing::info!("Successfully migrated v0 keyring '{name}' to v1",);
                        return Ok((name.to_owned(), label, alias, Keyring::Unlocked(unlocked)));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to migrate v0 keyring '{name}': {e}. Creating locked placeholder collection.",
                        );
                    }
                }

                // Migration failed - create locked placeholder and register for
                // pending migration
                tracing::debug!(
                    "Creating locked placeholder for v0 keyring '{}', will migrate on unlock",
                    name
                );

                let locked = LockedKeyring::open(name).await?;
                self.pending_migrations
                    .lock()
                    .await
                    .insert(name.to_owned(), migration);

                Keyring::Locked(locked)
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        Ok((name.to_owned(), label, alias, keyring))
    }

    /// Initialize the service with collections and start client disconnect
    /// handler
    pub(crate) async fn initialize(
        &self,
        connection: zbus::Connection,
        mut discovered_keyrings: Vec<(String, String, String, Keyring)>, /* (name, label, alias,
                                                                          * keyring) */
        secret: Option<Secret>,
        auto_create_default: bool,
    ) -> Result<(), Error> {
        self.connection.set(connection.clone()).unwrap();

        let object_server = connection.object_server();
        let mut collections = self.collections.lock().await;

        // Check if we have a default collection
        let has_default = discovered_keyrings.iter().any(|(_, _, alias, _)| {
            alias == oo7::dbus::Service::DEFAULT_COLLECTION || alias == Self::LOGIN_ALIAS
        });

        if !has_default && auto_create_default {
            tracing::info!("No default collection found, creating 'Login' keyring");

            let keyring = if let Some(secret) = secret {
                UnlockedKeyring::open_at(&self.data_dir, Self::LOGIN_ALIAS, Some(secret))
                    .await
                    .map(Keyring::Unlocked)
            } else {
                LockedKeyring::open_at(&self.data_dir, Self::LOGIN_ALIAS)
                    .await
                    .map(Keyring::Locked)
            };

            let keyring = keyring.inspect_err(|e| {
                tracing::error!("Failed to create default Login keyring: {}", e);
            })?;

            let is_locked = if keyring.is_locked() {
                "locked"
            } else {
                "unlocked"
            };
            discovered_keyrings.push((
                Self::LOGIN_ALIAS.to_owned(),
                "Login".to_owned(),
                oo7::dbus::Service::DEFAULT_COLLECTION.to_owned(),
                keyring,
            ));

            tracing::info!("Created default 'Login' collection ({})", is_locked);
        }

        // Build all collections under the lock, then register on D-Bus after
        // releasing it to avoid deadlocks with incoming calls.
        let mut built_collections: Vec<(Collection, String)> = Vec::new();

        for (name, label, alias, keyring) in discovered_keyrings {
            tracing::info!("Setting up collection '{name}' (alias: {alias}).");
            let (unique_label, unique_alias) =
                Self::make_unique_label_and_alias(&collections, &label, &alias);
            let collection =
                Collection::new(&name, &unique_label, &unique_alias, self.clone(), keyring).await;
            collections.insert(collection.path().to_owned().into(), collection.clone());
            built_collections.push((collection, unique_alias));
        }

        // Always create session collection (always temporary)
        let session_collection = Collection::new(
            "session",
            "session",
            oo7::dbus::Service::SESSION_COLLECTION,
            self.clone(),
            Keyring::Unlocked(UnlockedKeyring::temporary(Secret::random().unwrap()).await?),
        )
        .await;
        collections.insert(
            session_collection.path().to_owned().into(),
            session_collection.clone(),
        );

        drop(collections);

        // Now register on D-Bus and dispatch items without holding the lock
        for (collection, alias) in &built_collections {
            collection.dispatch_items().await?;
            object_server
                .at(collection.path(), collection.clone())
                .await?;

            if alias == oo7::dbus::Service::DEFAULT_COLLECTION {
                object_server
                    .at(DEFAULT_COLLECTION_ALIAS_PATH, collection.clone())
                    .await?;
            }
        }

        let session_path = session_collection.path().to_owned();
        object_server.at(&session_path, session_collection).await?;

        // Spawn client disconnect handler
        let service = self.clone();
        tokio::spawn(async move { service.on_client_disconnect().await });

        // Spawn stale session cleanup task
        let service = self.clone();
        tokio::spawn(async move { service.cleanup_stale_sessions().await });

        Ok(())
    }

    async fn on_client_disconnect(&self) -> zbus::Result<()> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender("org.freedesktop.DBus")?
            .interface("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .arg(2, "")?
            .build();
        let mut stream = zbus::MessageStream::for_match_rule(rule, self.connection(), None).await?;
        while let Some(message) = stream.try_next().await? {
            let body = message.body();
            let Ok((_name, old_owner, new_owner)) =
                body.deserialize::<(String, Optional<UniqueName<'_>>, Optional<UniqueName<'_>>)>()
            else {
                continue;
            };
            debug_assert!(new_owner.is_none()); // We enforce that in the matching rule
            let old_owner = old_owner
                .as_ref()
                .expect("A disconnected client requires an old_owner");
            self.revoke_access(old_owner).await;
            if let Some(session) = self.session_from_sender(old_owner).await {
                let client_name = match session.peer_info() {
                    Some(info) => format!("{old_owner} ({info})"),
                    None => old_owner.to_string(),
                };
                session.mark_stale().await;
                tracing::info!(
                    "Client {} disconnected. Session: {} marked for cleanup.",
                    client_name,
                    session.path()
                );
            }
        }
        Ok(())
    }

    /// Unlock `objects` for `client`: what [`Self::unlock`] does, callable
    /// without a message header.
    pub async fn unlock_for(
        &self,
        client: Option<OwnedUniqueName>,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        if self.per_client_access() {
            return self.unlock_for_client(client, objects).await;
        }

        tracing::info!("Unlock requested for {} objects.", objects.len());
        let (unlocked, not_unlocked) = self.set_locked(false, &objects).await?;
        if !not_unlocked.is_empty() {
            // Extract the label and collection before creating the prompt
            let label = self.extract_label_from_objects(&not_unlocked).await;
            let collection = self.extract_collection_from_objects(&not_unlocked).await;

            let prompt = Prompt::new(self.clone(), PromptRole::Unlock, label, collection).await;
            let path = OwnedObjectPath::from(prompt.path().clone());

            // Create the unlock action
            let service = self.clone();
            let action = PromptAction::new(move |secret: Option<Secret>| async move {
                // The prompter will handle secret validation
                // Here we just perform the unlock operation

                // First, check for pending migrations (without holding
                // collections lock)
                for object in &not_unlocked {
                    let collection = {
                        let collections = service.collections.lock().await;
                        collections.get(object).cloned()
                    };

                    if let Some(collection) = collection {
                        // Check if this collection has a pending migration by
                        // name
                        let migration_opt = {
                            let pending = service.pending_migrations.lock().await;
                            pending.get(collection.name()).cloned()
                        };

                        if let Some(migration) = migration_opt {
                            let migration_name = migration.name();
                            tracing::debug!(
                                "Attempting migration for '{}' during unlock",
                                migration_name
                            );

                            // Attempt migration with the provided secret (no
                            // locks held)
                            match migration.migrate(&service.data_dir, secret.as_ref()).await {
                                Ok(unlocked_keyring) => {
                                    tracing::info!(
                                        "Successfully migrated '{}' during unlock",
                                        migration_name
                                    );

                                    // Replace the keyring in the collection
                                    let mut keyring_guard = collection.keyring.write().await;
                                    *keyring_guard = Some(Keyring::Unlocked(unlocked_keyring));
                                    drop(keyring_guard);

                                    // Dispatch items from the migrated keyring
                                    if let Err(e) = collection.dispatch_items().await {
                                        tracing::error!(
                                            "Failed to dispatch items after migration: {}",
                                            e
                                        );
                                    }

                                    // Remove from pending migrations
                                    service
                                        .pending_migrations
                                        .lock()
                                        .await
                                        .remove(migration_name);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to migrate '{}' during unlock: {}",
                                        migration_name,
                                        e
                                    );
                                    let _ = collection.set_locked(false, secret.clone()).await;
                                }
                            }
                        } else {
                            // Normal unlock
                            let _ = collection.set_locked(false, secret.clone()).await;
                        }
                    } else {
                        // Try to find as item within collections
                        let collections = service.collections.lock().await;
                        let mut found_collection = None;
                        for collection in collections.values() {
                            if let Some(item) = collection.item_from_path(object).await {
                                found_collection = Some((
                                    collection.clone(),
                                    item.clone(),
                                    collection.is_locked().await,
                                ));
                                break;
                            }
                        }
                        drop(collections);

                        if let Some((collection, item, is_locked)) = found_collection {
                            if is_locked {
                                let _ = collection.set_locked(false, secret.clone()).await;
                            } else {
                                let keyring = collection.keyring.read().await;
                                match keyring.as_ref() {
                                    Some(k) if !k.is_locked() => {
                                        let _ = item.set_locked(false, k.as_unlocked()).await;
                                    }
                                    _ => {
                                        drop(keyring);
                                        let _ = collection.set_locked(false, secret.clone()).await;
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Value::new(not_unlocked).try_into_owned().unwrap())
            });

            prompt.set_action(action).await;

            self.prompts
                .lock()
                .await
                .insert(path.clone(), prompt.clone());

            self.object_server().at(&path, prompt).await?;
            return Ok((unlocked, path));
        }

        Ok((unlocked, OwnedObjectPath::default()))
    }

    /// [`Self::unlock_for`] with per-client access: an item is unlocked for
    /// `client` once its keyring is unlocked and the client was allowed to use
    /// it. One prompt asks for whatever is missing: the keyring's password
    /// first if it is locked, then whether the client may use the items.
    async fn unlock_for_client(
        &self,
        client: Option<OwnedUniqueName>,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ServiceError> {
        let Some(client) = client else {
            return Err(custom_service_error("The client has no bus name."));
        };

        let mut unlocked = Vec::new();
        let mut pending = Vec::new();
        let mut locked_collection = None;
        for object in objects {
            if let Some(collection) = self.collection_from_path(&object).await {
                if collection.is_locked().await {
                    locked_collection.get_or_insert(collection);
                    pending.push(object);
                } else {
                    unlocked.push(object);
                }
            } else if let Some((collection, _item)) = self.item_from_path(&object).await {
                if collection.is_locked().await {
                    locked_collection.get_or_insert(collection);
                    pending.push(object);
                } else if self.may_access(Some(&client), &object).await {
                    unlocked.push(object);
                } else {
                    pending.push(object);
                }
            } else {
                tracing::warn!("Object: {} does not exist.", object);
            }
        }

        if pending.is_empty() {
            return Ok((unlocked, OwnedObjectPath::default()));
        }

        let (role, collection) = match locked_collection {
            Some(collection) => (PromptRole::Unlock, Some(collection)),
            None => (
                PromptRole::Access,
                self.extract_collection_from_objects(&pending).await,
            ),
        };
        let label = match &collection {
            Some(collection) => collection.label().await,
            None => String::new(),
        };
        let prompt = Prompt::new(self.clone(), role, label, collection)
            .await
            .with_client(client)
            .with_access(AccessStep {
                operation: Operation::Read,
                objects: pending.clone(),
            });
        let path = OwnedObjectPath::from(prompt.path().clone());

        // The socket prompter unlocked the keyring and recorded the access
        // before it runs this.
        let action = PromptAction::new(move |_secret: Option<Secret>| async move {
            Ok(Value::new(pending).try_into_owned().unwrap())
        });
        prompt.set_action(action).await;

        self.register_prompt(path.clone(), prompt.clone()).await;
        self.object_server().at(&path, prompt).await?;

        Ok((unlocked, path))
    }

    pub fn set_options(&self, options: Options) {
        *self.options.write().unwrap() = options;
    }

    pub fn per_client_access(&self) -> bool {
        self.options.read().unwrap().per_client_access
    }

    pub fn prompter_socket(&self) -> Option<PathBuf> {
        self.options.read().unwrap().prompter_socket.clone()
    }

    /// Whether `client` may use `item`. Always with per-client access off;
    /// otherwise once an access prompt allowed it, until the client leaves the
    /// bus. Says nothing about the item's keyring being unlocked.
    pub async fn may_access(
        &self,
        client: Option<&OwnedUniqueName>,
        item: &ObjectPath<'_>,
    ) -> bool {
        if !self.per_client_access() {
            return true;
        }
        let Some(client) = client else {
            return false;
        };
        self.access
            .lock()
            .await
            .get(client)
            .is_some_and(|items| items.contains(&OwnedObjectPath::from(item.to_owned())))
    }

    pub async fn grant_access(&self, client: &OwnedUniqueName, items: &[OwnedObjectPath]) {
        if !self.per_client_access() {
            return;
        }
        tracing::info!("Client {client} allowed to use {} item(s).", items.len());
        self.access
            .lock()
            .await
            .entry(client.clone())
            .or_default()
            .extend(items.iter().cloned());
    }

    pub async fn revoke_access(&self, client: &UniqueName<'_>) {
        let client = OwnedUniqueName::from(client.to_owned());
        if self.access.lock().await.remove(&client).is_some() {
            tracing::info!("Client {client} left, its access is dropped.");
        }
    }

    /// The objects of an access step the client still has to be allowed:
    /// items it may not use yet when reading, every object when deleting.
    pub(crate) async fn needs_access(
        &self,
        client: &OwnedUniqueName,
        step: &AccessStep,
    ) -> Vec<OwnedObjectPath> {
        let mut needed = Vec::new();
        for object in &step.objects {
            match step.operation {
                Operation::Delete => needed.push(object.clone()),
                Operation::Read => {
                    if self.item_from_path(object).await.is_some()
                        && !self.may_access(Some(client), object).await
                    {
                        needed.push(object.clone());
                    }
                }
            }
        }
        needed
    }

    /// What an access prompt shows for `objects`: an item's label, or a
    /// collection's.
    pub(crate) async fn labels_of(&self, objects: &[OwnedObjectPath]) -> Vec<String> {
        let mut labels = Vec::new();
        for object in objects {
            if let Some((_collection, item)) = self.item_from_path(object).await {
                labels.push(item.label().await.unwrap_or_else(|_| object.to_string()));
            } else if let Some(collection) = self.collection_from_path(object).await {
                labels.push(collection.label().await);
            }
        }
        labels
    }

    pub(crate) async fn item_from_path(&self, path: &ObjectPath<'_>) -> Option<(Collection, Item)> {
        let collections = self.collections.lock().await;
        for collection in collections.values() {
            if let Some(item) = collection.item_from_path(path).await {
                return Some((collection.clone(), item));
            }
        }
        None
    }

    /// The client a prompt is for, with its pid and pidfd: from the bus
    /// (`GetConnectionCredentials`), or from the socket on a peer-to-peer
    /// connection.
    pub(crate) async fn caller(&self, client: Option<&OwnedUniqueName>) -> Caller {
        let connection = self.connection();
        let from = |credentials: &zbus::fdo::ConnectionCredentials| Caller {
            bus_name: client.cloned(),
            pid: credentials.process_id(),
            pidfd: credentials
                .process_fd()
                .and_then(|fd| fd.as_fd().try_clone_to_owned().ok()),
        };

        if connection.is_bus() {
            let Some(client) = client else {
                return Caller::default();
            };
            let credentials = match zbus::fdo::DBusProxy::new(connection).await {
                Ok(proxy) => {
                    proxy
                        .get_connection_credentials(BusName::from((**client).clone()))
                        .await
                }
                Err(err) => Err(err.into()),
            };
            match credentials {
                Ok(credentials) => from(&credentials),
                Err(err) => {
                    tracing::warn!("Failed to get the credentials of {client}: {err}");
                    Caller {
                        bus_name: Some(client.clone()),
                        ..Default::default()
                    }
                }
            }
        } else {
            match connection.peer_creds().await {
                Ok(credentials) => from(credentials),
                Err(err) => {
                    tracing::warn!("Failed to get the peer's credentials: {err}");
                    Caller {
                        bus_name: client.cloned(),
                        ..Default::default()
                    }
                }
            }
        }
    }

    /// With the socket prompter, a search that finds a keyring locked asks for
    /// its password and waits for it, instead of answering that nothing
    /// matches: a locked keyring cannot be searched (its attributes are hashed
    /// with a key derived from the password), and an empty answer makes clients
    /// store a new secret over the one they could not see. Refused, the search
    /// fails with `IsLocked`. A keyring with no file yet has nothing to find,
    /// so it is not asked for.
    async fn unlock_keyrings_for_search(
        &self,
        client: Option<&OwnedUniqueName>,
    ) -> Result<(), ServiceError> {
        if self.prompter_socket().is_none() {
            return Ok(());
        }

        let mut locked = Vec::new();
        for collection in self.collections.lock().await.values() {
            if collection.is_locked().await && !collection.is_new().await {
                locked.push(collection.clone());
            }
        }

        for collection in locked {
            if !self.unlock_for_search(&collection, client).await {
                return Err(ServiceError::IsLocked(format!(
                    "The keyring `{}` is locked.",
                    collection.label().await
                )));
            }
        }
        Ok(())
    }

    /// Unlock `collection` through the socket prompter, once for all the
    /// searches that wait on it at the same time.
    async fn unlock_for_search(
        &self,
        collection: &Collection,
        client: Option<&OwnedUniqueName>,
    ) -> bool {
        let path = OwnedObjectPath::from(collection.path().to_owned());
        let mut outcome = {
            let mut unlocks = self.search_unlocks.lock().await;
            match unlocks.get(&path) {
                Some(outcome) => outcome.clone(),
                None => {
                    let (sender, outcome) = watch::channel(None);
                    unlocks.insert(path.clone(), outcome.clone());

                    let caller = self.caller(client).await;
                    let service = self.clone();
                    let collection = collection.clone();
                    // Spawned: the keyring is unlocked even if the client that
                    // searched has given up waiting.
                    tokio::spawn(async move {
                        let unlocked = service.ask_unlock(&collection, caller).await;
                        service.search_unlocks.lock().await.remove(&path);
                        let _ = sender.send(Some(unlocked));
                    });
                    outcome
                }
            }
        };

        match outcome.wait_for(Option::is_some).await {
            Ok(unlocked) => unlocked.unwrap_or(false),
            Err(_) => false,
        }
    }

    async fn ask_unlock(&self, collection: &Collection, caller: Caller) -> bool {
        let Some(socket) = self.prompter_socket() else {
            return false;
        };
        let mut session = match socket_prompter::Session::connect(&socket, caller).await {
            Ok(session) => session,
            Err(err) => {
                tracing::error!(
                    "Failed to reach the prompter at {}: {err}",
                    socket.display()
                );
                return false;
            }
        };
        let label = collection.label().await;
        match crate::prompt::ask_password(
            &mut session,
            PromptRole::Unlock,
            &label,
            None,
            Some(collection),
            None,
        )
        .await
        {
            Ok(secret) => secret.is_some(),
            Err(err) => {
                tracing::error!("Failed to unlock {label} for a search: {err}");
                false
            }
        }
    }

    async fn cleanup_stale_sessions(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let stale_paths: Vec<_> = {
                let sessions = self.sessions.lock().await;
                let mut paths = Vec::new();
                for (path, session) in sessions.iter() {
                    if session.is_stale().await {
                        paths.push(path.clone());
                    }
                }
                paths
            };
            for path in stale_paths {
                if let Some(session) = self.session(&path).await {
                    match session.close().await {
                        Ok(_) => tracing::info!("Stale session {} cleaned up.", path),
                        Err(err) => {
                            tracing::error!("Failed to clean up stale session {}: {}", path, err)
                        }
                    }
                }
            }
        }
    }

    pub async fn set_locked(
        &self,
        locked: bool,
        objects: &[OwnedObjectPath],
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), ServiceError> {
        let mut without_prompt = Vec::new();
        let mut with_prompt = Vec::new();
        let collections = self.collections.lock().await;

        for object in objects {
            let resolved = Self::resolve_alias(&collections, object)
                .await
                .unwrap_or_else(|| object.clone());
            let mut found = false;
            for (path, collection) in collections.iter() {
                let collection_locked = collection.is_locked().await;
                if resolved == *path {
                    found = true;
                    if collection_locked == locked {
                        tracing::debug!(
                            "Collection: {} is already {}.",
                            resolved,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(resolved.clone());
                    } else if locked {
                        // Locking never requires a prompt
                        collection.set_locked(true, None).await?;
                        without_prompt.push(resolved.clone());
                    } else {
                        // Unlocking may require a prompt
                        with_prompt.push(resolved.clone());
                    }
                    break;
                } else if let Some(item) = collection.item_from_path(&resolved).await {
                    found = true;
                    // If collection is locked, can't perform any item
                    // lock/unlock operations
                    if collection_locked {
                        // Unlocking an item when collection is locked requires
                        // unlocking collection
                        if !locked {
                            with_prompt.push(resolved.clone());
                        } else {
                            // Can't lock an item when collection is locked
                            return Err(ServiceError::IsLocked(format!(
                                "Cannot lock item {} when collection is locked",
                                resolved
                            )));
                        }
                    } else if locked == item.is_locked().await {
                        tracing::debug!(
                            "Item: {} is already {}.",
                            resolved,
                            if locked { "locked" } else { "unlocked" }
                        );
                        without_prompt.push(resolved.clone());
                    } else {
                        let keyring = collection.keyring.read().await;
                        match keyring.as_ref() {
                            Some(k) if !k.is_locked() => {
                                item.set_locked(locked, k.as_unlocked()).await?;
                                without_prompt.push(resolved.clone());
                            }
                            _ => {
                                if locked {
                                    return Err(ServiceError::IsLocked(format!(
                                        "Cannot lock item {} when collection is locked",
                                        resolved
                                    )));
                                } else {
                                    with_prompt.push(resolved.clone());
                                }
                            }
                        }
                    }
                    break;
                }
            }
            if !found {
                tracing::warn!("Object: {} does not exist.", object);
            }
        }

        Ok((without_prompt, with_prompt))
    }

    pub fn connection(&self) -> &zbus::Connection {
        self.connection.get().unwrap()
    }

    pub fn object_server(&self) -> &zbus::ObjectServer {
        self.connection().object_server()
    }

    async fn resolve_alias(
        collections: &HashMap<OwnedObjectPath, Collection>,
        path: &ObjectPath<'_>,
    ) -> Option<OwnedObjectPath> {
        let alias = path.strip_prefix("/org/freedesktop/secrets/aliases/")?;
        let alias_to_find = if alias == Self::LOGIN_ALIAS {
            oo7::dbus::Service::DEFAULT_COLLECTION
        } else {
            alias
        };
        for (real_path, collection) in collections.iter() {
            if collection.alias().await == alias_to_find {
                return Some(real_path.clone());
            }
        }
        None
    }

    pub async fn collection_from_path(&self, path: &ObjectPath<'_>) -> Option<Collection> {
        let collections = self.collections.lock().await;
        if let Some(collection) = collections.get(path).cloned() {
            return Some(collection);
        }
        let resolved = Self::resolve_alias(&collections, path).await?;
        collections.get(&resolved).cloned()
    }

    pub fn session_index(&self) -> u32 {
        self.session_index.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) async fn session_from_sender(&self, sender: &UniqueName<'_>) -> Option<Session> {
        let sessions = self.sessions.lock().await;

        sessions.values().find(|s| s.sender() == sender).cloned()
    }

    pub async fn peer_display_name(&self, sender: &UniqueName<'_>) -> String {
        match self.session_from_sender(sender).await {
            Some(session) => match session.peer_info() {
                Some(info) => format!("{sender} ({info})"),
                None => sender.to_string(),
            },
            None => sender.to_string(),
        }
    }

    pub async fn session(&self, path: &ObjectPath<'_>) -> Option<Session> {
        let session = self.sessions.lock().await.get(path).cloned()?;
        session.unmark_stale().await;
        Some(session)
    }

    pub async fn remove_session(&self, path: &ObjectPath<'_>) {
        self.sessions.lock().await.remove(path);
    }

    pub async fn remove_collection(&self, path: &ObjectPath<'_>) {
        self.collections.lock().await.remove(path);

        if let Ok(signal_emitter) =
            self.signal_emitter(oo7::dbus::api::Service::PATH.as_deref().unwrap())
        {
            let _ = self.collections_changed(&signal_emitter).await;
        }
    }

    pub fn prompt_index(&self) -> u32 {
        self.prompt_index.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn prompt(&self, path: &ObjectPath<'_>) -> Option<Prompt> {
        self.prompts.lock().await.get(path).cloned()
    }

    pub async fn remove_prompt(&self, path: &ObjectPath<'_>) {
        self.prompts.lock().await.remove(path);
        // Also clean up pending collection if it exists
        self.pending_collections.lock().await.remove(path);
    }

    pub async fn register_prompt(&self, path: OwnedObjectPath, prompt: Prompt) {
        self.prompts.lock().await.insert(path, prompt);
    }

    pub async fn pending_collection(
        &self,
        prompt_path: &ObjectPath<'_>,
    ) -> Option<(String, String)> {
        self.pending_collections
            .lock()
            .await
            .get(prompt_path)
            .cloned()
    }

    pub async fn create_collection_with_secret(
        &self,
        label: &str,
        alias: &str,
        secret: Option<Secret>,
    ) -> Result<OwnedObjectPath, ServiceError> {
        // Create a persistent keyring with the provided secret
        let keyring = UnlockedKeyring::open_at(&self.data_dir, &label.to_lowercase(), secret)
            .await
            .map_err(|err| custom_service_error(&format!("Failed to create keyring: {err}")))?;

        // Write the keyring file to disk immediately
        keyring
            .write()
            .await
            .map_err(|err| custom_service_error(&format!("Failed to write keyring file: {err}")))?;

        let keyring = Keyring::Unlocked(keyring);
        let name = label.to_lowercase();

        // Create the collection with unique label and alias
        let (unique_label, unique_alias) = {
            let collections = self.collections.lock().await;
            Self::make_unique_label_and_alias(&collections, label, alias)
        };
        let collection =
            Collection::new(&name, &unique_label, &unique_alias, self.clone(), keyring).await;
        let collection_path: OwnedObjectPath = collection.path().to_owned().into();

        // Register with object server
        self.object_server()
            .at(collection.path(), collection.clone())
            .await?;

        // Add to collections
        self.collections
            .lock()
            .await
            .insert(collection_path.clone(), collection);

        // Emit CollectionCreated signal
        let service_path = oo7::dbus::api::Service::PATH.as_ref().unwrap();
        let signal_emitter = self.signal_emitter(service_path)?;
        Service::collection_created(&signal_emitter, &collection_path).await?;

        // Emit PropertiesChanged for Collections property to invalidate client
        // cache
        self.collections_changed(&signal_emitter).await?;

        tracing::info!(
            "Collection `{}` created with label '{}'",
            collection_path,
            label
        );

        Ok(collection_path)
    }

    pub async fn complete_collection_creation(
        &self,
        prompt_path: &ObjectPath<'_>,
        secret: Option<Secret>,
    ) -> Result<OwnedObjectPath, ServiceError> {
        let Some((label, alias)) = self.pending_collection(prompt_path).await else {
            return Err(ServiceError::NoSuchObject(format!(
                "No pending collection for prompt `{prompt_path}`"
            )));
        };

        let collection_path = self
            .create_collection_with_secret(&label, &alias, secret)
            .await?;

        self.pending_collections.lock().await.remove(prompt_path);

        Ok(collection_path)
    }

    pub fn signal_emitter<'a, P>(
        &self,
        path: P,
    ) -> Result<zbus::object_server::SignalEmitter<'a>, oo7::dbus::ServiceError>
    where
        P: TryInto<ObjectPath<'a>>,
        P::Error: Into<zbus::Error>,
    {
        let signal_emitter = zbus::object_server::SignalEmitter::new(self.connection(), path)?;

        Ok(signal_emitter)
    }

    /// Extract the collection label from a list of object paths
    /// The objects can be either collections or items
    async fn extract_label_from_objects(&self, objects: &[OwnedObjectPath]) -> String {
        if objects.is_empty() {
            return String::new();
        }

        // Check if at least one of the objects is a Collection
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return collection.label().await;
            }
        }

        // Get the collection path from the first item
        // assumes all items are from the same collection
        if let Some(path_str) = objects.first().and_then(|p| p.as_str().rsplit_once('/')) {
            let collection_path = path_str.0;
            if let Ok(obj_path) = ObjectPath::try_from(collection_path)
                && let Some(collection) = self.collection_from_path(&obj_path).await
            {
                return collection.label().await;
            }
        }

        String::new()
    }

    /// Extract the collection from a list of object paths
    /// The objects can be either collections or items
    async fn extract_collection_from_objects(
        &self,
        objects: &[OwnedObjectPath],
    ) -> Option<Collection> {
        if objects.is_empty() {
            return None;
        }

        // Check if at least one of the objects is a Collection
        for object in objects {
            if let Some(collection) = self.collection_from_path(object).await {
                return Some(collection);
            }
        }

        // Get the collection path from the first item
        // (assumes all items are from the same collection)
        let path = objects
            .first()
            .unwrap()
            .as_str()
            .rsplit_once('/')
            .map(|(parent, _)| parent)?;
        self.collection_from_path(&ObjectPath::try_from(path).unwrap())
            .await
    }

    /// Attempt to migrate pending keyrings with the provided secret
    /// Returns a list of successfully migrated keyring names
    pub async fn migrate_pending_keyrings(&self, secret: &Secret) -> Vec<String> {
        let mut migrated = Vec::new();
        let mut pending = self.pending_migrations.lock().await;
        let mut to_remove = Vec::new();

        for (name, migration) in pending.iter() {
            tracing::debug!("Attempting to migrate pending keyring: {name}");

            match migration.migrate(&self.data_dir, Some(secret)).await {
                Ok(unlocked) => {
                    let label = migration.label();
                    let alias = migration.alias();

                    // Create a collection for this migrated keyring with unique
                    // label and alias
                    let (unique_label, unique_alias) = {
                        let collections = self.collections.lock().await;
                        Self::make_unique_label_and_alias(&collections, label, alias)
                    };
                    let keyring = Keyring::Unlocked(unlocked);
                    let collection =
                        Collection::new(name, &unique_label, &unique_alias, self.clone(), keyring)
                            .await;
                    let collection_path: OwnedObjectPath = collection.path().to_owned().into();

                    // Dispatch items
                    if let Err(e) = collection.dispatch_items().await {
                        tracing::error!(
                            "Failed to dispatch items for migrated keyring '{name}': {e}",
                        );
                        continue;
                    }

                    if let Err(e) = self
                        .object_server()
                        .at(collection.path(), collection.clone())
                        .await
                    {
                        tracing::error!(
                            "Failed to register migrated collection '{name}' with object server: {e}",
                        );
                        continue;
                    }

                    self.collections
                        .lock()
                        .await
                        .insert(collection_path.clone(), collection.clone());

                    if alias == oo7::dbus::Service::DEFAULT_COLLECTION
                        && let Err(e) = self
                            .object_server()
                            .at(DEFAULT_COLLECTION_ALIAS_PATH, collection)
                            .await
                    {
                        tracing::error!(
                            "Failed to register default alias for migrated collection '{name}': {e}",
                        );
                    }

                    if let Ok(signal_emitter) =
                        self.signal_emitter(oo7::dbus::api::Service::PATH.as_ref().unwrap())
                    {
                        let _ =
                            Service::collection_created(&signal_emitter, &collection_path).await;
                        let _ = self.collections_changed(&signal_emitter).await;
                    }

                    tracing::info!("Migrated keyring '{name}' added as collection",);
                    migrated.push(name.clone());
                    to_remove.push(name.clone());
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to migrate keyring '{name}' found at {} with provided secret: {e}",
                        migration.path().display()
                    );
                }
            }
        }

        for name in &to_remove {
            pending.remove(name);
        }

        migrated
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unencrypted_tests;
