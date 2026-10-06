// Per-client access, the socket prompter, and the first keyring created
// through it. The client of `TestServiceSetup` is `:p2p.test` (a p2p
// connection has no bus to name it); `call_as` speaks as a second client on
// the same connection.

use std::{collections::HashMap, sync::Arc};

use oo7::{Secret, dbus};
use zbus::{proxy::Defaults, zvariant::OwnedObjectPath};

use crate::{
    service::{Options, Service},
    tests::{MockSocketPrompter, SocketReply, TestServiceSetup, call_as, create_p2p_connection},
};

const OTHER_CLIENT: &str = ":1.99";
const ATTRIBUTES: [(&str, &str); 1] = [("app", "access-test")];

/// A service with an unlocked default keyring holding one item stored before
/// per-client access was on, so no client may use it yet; then the options
/// are set to per-client access through `prompter`.
async fn setup_with_item(
    prompter: &MockSocketPrompter,
) -> Result<(TestServiceSetup, dbus::api::Item), Box<dyn std::error::Error>> {
    let setup = TestServiceSetup::plain_session(true).await?;
    let secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), Secret::text("s3cret"));
    let item = setup
        .default_collection()
        .await?
        .create_item("Test Item", &ATTRIBUTES, &secret, true, None)
        .await?;

    setup.server.set_options(Options {
        per_client_access: true,
        prompter_socket: Some(prompter.path.clone()),
    });
    Ok((setup, item))
}

fn attributes() -> HashMap<String, String> {
    ATTRIBUTES
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// `SearchItems` as `OTHER_CLIENT`: (unlocked, locked).
async fn search_as_other(
    setup: &TestServiceSetup,
) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), Box<dyn std::error::Error>> {
    let reply = call_as(
        &setup.client_conn,
        OTHER_CLIENT,
        &oo7::dbus::api::Service::PATH.as_ref().unwrap().as_ref(),
        "org.freedesktop.Secret.Service",
        "SearchItems",
        &(attributes(),),
    )
    .await?;
    Ok(reply.body().deserialize()?)
}

fn paths(items: &[dbus::api::Item]) -> Vec<OwnedObjectPath> {
    items
        .iter()
        .map(|item| item.inner().path().to_owned().into())
        .collect()
}

#[tokio::test]
async fn unallowed_client_sees_items_locked() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([]);
    let (setup, item) = setup_with_item(&prompter).await?;

    let (unlocked, locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert!(
        unlocked.is_empty(),
        "Nothing should be unlocked for the client"
    );
    assert_eq!(paths(&locked), paths(std::slice::from_ref(&item)));
    assert!(locked[0].is_locked().await?, "Locked should be true for it");

    #[allow(clippy::mutable_key_type)]
    let secrets = setup.service_api.secrets(&locked, &setup.session).await?;
    assert!(secrets.is_empty(), "GetSecrets should skip the item");
    assert!(
        matches!(
            item.secret(&setup.session).await,
            Err(oo7::dbus::Error::Service(
                oo7::dbus::ServiceError::IsLocked(_)
            ))
        ),
        "GetSecret should say the item is locked"
    );
    assert!(
        prompter.requests().is_empty(),
        "Nothing should be asked yet"
    );
    Ok(())
}

#[tokio::test]
async fn allowed_client_reads_and_another_stays_locked() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([SocketReply::Allow]);
    let (setup, item) = setup_with_item(&prompter).await?;

    let unlocked = setup
        .service_api
        .unlock(&[item.inner().path()], None)
        .await?;
    assert_eq!(unlocked, paths(std::slice::from_ref(&item)));

    // What the prompter was asked, and who it was told asks.
    let requests = prompter.requests();
    assert_eq!(requests.len(), 1, "One access request: {requests:?}");
    let request = &requests[0].json;
    assert_eq!(request["version"], 1);
    assert_eq!(request["type"], "access");
    assert_eq!(request["operation"], "read");
    assert_eq!(request["keyring"], "Login");
    assert_eq!(request["items"], serde_json::json!(["Test Item"]));
    assert!(
        request["prompt"]
            .as_str()
            .unwrap()
            .starts_with("/org/freedesktop/secrets/prompt/")
    );
    assert_eq!(request["caller"]["bus_name"], ":p2p.test");
    assert_eq!(request["caller"]["pid"], std::process::id());
    assert_eq!(request["caller"]["pidfd"], true);
    assert_eq!(
        requests[0].pidfd_pid,
        Some(std::process::id()),
        "The pidfd should be the caller's"
    );

    // Allowed: it reads.
    let (unlocked, locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert_eq!(paths(&unlocked), paths(std::slice::from_ref(&item)));
    assert!(locked.is_empty());
    let secret = item.secret(&setup.session).await?;
    assert_eq!(secret.value(), b"s3cret");

    // Another client still sees it locked, and gets no secret.
    let (unlocked, locked) = search_as_other(&setup).await?;
    assert!(unlocked.is_empty(), "Still locked for another client");
    assert_eq!(locked, paths(std::slice::from_ref(&item)));
    let reply = call_as(
        &setup.client_conn,
        OTHER_CLIENT,
        &item.inner().path().as_ref(),
        "org.freedesktop.Secret.Item",
        "GetSecret",
        &(setup.session.inner().path(),),
    )
    .await;
    assert!(
        matches!(&reply, Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == "org.freedesktop.Secret.Error.IsLocked"),
        "GetSecret as another client: {reply:?}"
    );
    let reply = call_as(
        &setup.client_conn,
        OTHER_CLIENT,
        &item.inner().path().as_ref(),
        "org.freedesktop.DBus.Properties",
        "Get",
        &("org.freedesktop.Secret.Item", "Locked"),
    )
    .await?;
    let locked: zbus::zvariant::OwnedValue = reply.body().deserialize()?;
    assert!(bool::try_from(locked)?, "Locked for another client");

    // The decision lasts until the client leaves the bus.
    setup
        .server
        .revoke_access(&zbus::names::UniqueName::try_from(":p2p.test")?)
        .await;
    let (unlocked, _locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert!(unlocked.is_empty(), "Locked again after the client left");
    Ok(())
}

#[tokio::test]
async fn dismissed_access_is_dismissed() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([SocketReply::Deny]);
    let (setup, item) = setup_with_item(&prompter).await?;

    let result = setup.service_api.unlock(&[item.inner().path()], None).await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::Dismissed)),
        "Refused should be dismissed: {result:?}"
    );

    // Never an empty search: the item is still found, locked.
    let (unlocked, locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert!(unlocked.is_empty());
    assert_eq!(paths(&locked), paths(std::slice::from_ref(&item)));
    Ok(())
}

#[tokio::test]
async fn dismissing_the_prompt_closes_the_prompter() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([SocketReply::Hold]);
    let (setup, item) = setup_with_item(&prompter).await?;

    let (_unlocked, prompt_path) = setup
        .server
        .unlock_for(
            Some(zbus::names::UniqueName::try_from(":p2p.test")?.into()),
            vec![item.inner().path().to_owned().into()],
        )
        .await?;
    let prompt = dbus::api::Prompt::new(&setup.client_conn, prompt_path.clone())
        .await?
        .unwrap();
    prompt.prompt(None).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(prompter.requests().len(), 1, "The request is open");

    prompt.dismiss().await?;
    tokio::time::timeout(tokio::time::Duration::from_secs(2), prompter.closed()).await?;
    assert!(setup.server.prompt(&prompt_path).await.is_none());
    Ok(())
}

#[tokio::test]
async fn password_for_a_read_also_allows_the_client() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([
        SocketReply::Password("wrong-password"),
        SocketReply::Password("test-password-long-enough"),
    ]);
    let (setup, item) = setup_with_item(&prompter).await?;
    let collection = setup
        .server
        .collection_from_path(setup.default_collection().await?.inner().path())
        .await
        .unwrap();
    collection.set_locked(true, None).await?;

    let unlocked = setup
        .service_api
        .unlock(&[item.inner().path()], None)
        .await?;
    assert_eq!(unlocked, paths(std::slice::from_ref(&item)));

    // The password card only: it says the password allows reading, and names
    // the caller, so no access card follows.
    let requests = prompter.requests();
    let types = requests
        .iter()
        .map(|r| r.json["type"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(types, ["unlock", "unlock"]);
    assert_eq!(requests[0].json["operation"], "read");
    assert_eq!(requests[0].pidfd_pid, Some(std::process::id()));
    assert!(requests[0].json.get("warning").is_none());
    assert_eq!(
        requests[1].json["warning"], "The unlock password was incorrect",
        "Asked again after a wrong password"
    );
    assert!(!collection.is_locked().await);
    assert_eq!(item.secret(&setup.session).await?.value(), b"s3cret");

    // A delete in a locked keyring: the password, which allows nothing, then
    // the delete card all the same.
    collection.set_locked(true, None).await?;
    prompter.set_replies([
        SocketReply::Password("test-password-long-enough"),
        SocketReply::Deny,
    ]);
    let result = item.delete(None).await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::Dismissed)),
        "{result:?}"
    );
    let requests = &prompter.requests()[2..];
    assert_eq!(requests[0].json["type"], "unlock");
    assert!(requests[0].json.get("operation").is_none());
    assert_eq!(requests[1].json["type"], "access");
    assert_eq!(requests[1].json["operation"], "delete");
    Ok(())
}

#[tokio::test]
async fn search_of_a_locked_keyring_asks_for_its_password() -> Result<(), Box<dyn std::error::Error>>
{
    let prompter = MockSocketPrompter::new([SocketReply::Password("test-password-long-enough")]);
    let (setup, item) = setup_with_item(&prompter).await?;
    let collection = setup
        .server
        .collection_from_path(setup.default_collection().await?.inner().path())
        .await
        .unwrap();
    collection.set_locked(true, None).await?;

    // The search waits for the password, then finds the item (locked for this
    // client, which has not been allowed yet).
    let (_unlocked, locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert_eq!(paths(&locked), paths(std::slice::from_ref(&item)));
    let requests = prompter.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].json["type"], "unlock");
    assert!(
        requests[0].json.get("prompt").is_none(),
        "Asked by the daemon itself"
    );
    assert_eq!(requests[0].pidfd_pid, Some(std::process::id()));

    // Refused: an error, never an empty answer.
    collection.set_locked(true, None).await?;
    prompter.set_replies([SocketReply::Deny]);
    let result = setup.service_api.search_items(&ATTRIBUTES).await;
    assert!(
        matches!(
            result,
            Err(oo7::dbus::Error::Service(
                oo7::dbus::ServiceError::IsLocked(_)
            ))
        ),
        "A refused unlock should fail the search: {result:?}"
    );
    Ok(())
}

#[tokio::test]
async fn deleting_always_asks() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([SocketReply::Allow, SocketReply::Deny]);
    let (setup, item) = setup_with_item(&prompter).await?;
    setup
        .service_api
        .unlock(&[item.inner().path()], None)
        .await?;

    // Allowed to read, it is still asked before deleting, and refused.
    let result = item.delete(None).await;
    assert!(
        matches!(result, Err(oo7::dbus::Error::Dismissed)),
        "{result:?}"
    );
    let requests = prompter.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].json["type"], "access");
    assert_eq!(requests[1].json["operation"], "delete");
    assert_eq!(requests[1].json["items"], serde_json::json!(["Test Item"]));
    let (unlocked, _locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert_eq!(unlocked.len(), 1, "Still there");

    prompter.set_replies([SocketReply::Allow]);
    item.delete(None).await?;
    let (unlocked, locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert!(unlocked.is_empty() && locked.is_empty(), "Deleted");
    Ok(())
}

#[tokio::test]
async fn stored_items_are_allowed_to_their_client_only() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([]);
    let (setup, old_item) = setup_with_item(&prompter).await?;

    // Storing with the attributes of an item it may not use does not replace
    // it: the new one is stored beside it, and only the new one is its own.
    let secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), Secret::text("mine"));
    let new_item = setup
        .default_collection()
        .await?
        .create_item("Mine", &ATTRIBUTES, &secret, true, None)
        .await?;
    let (unlocked, locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert_eq!(paths(&unlocked), paths(std::slice::from_ref(&new_item)));
    assert_eq!(paths(&locked), paths(std::slice::from_ref(&old_item)));
    assert_eq!(new_item.secret(&setup.session).await?.value(), b"mine");

    // Replacing its own item works as before.
    let secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), Secret::text("mine 2"));
    let own_attributes = [("app", "access-test"), ("user", "me")];
    let own = setup
        .default_collection()
        .await?
        .create_item("Mine 2", &own_attributes, &secret, true, None)
        .await?;
    let replaced = setup
        .default_collection()
        .await?
        .create_item("Mine 3", &own_attributes, &secret, true, None)
        .await?;
    let (unlocked, _locked) = setup.service_api.search_items(&own_attributes).await?;
    assert_eq!(paths(&unlocked), paths(std::slice::from_ref(&replaced)));
    assert_ne!(paths(&[own]), paths(&[replaced]));
    assert!(prompter.requests().is_empty(), "Nothing asked");
    Ok(())
}

/// A service started with no keyring on disk, in a temporary data
/// directory: the default keyring is created locked, without a file.
async fn setup_without_keyring(
    prompter: &MockSocketPrompter,
) -> Result<(TestServiceSetup, std::path::PathBuf), Box<dyn std::error::Error>> {
    let data_home = tempfile::tempdir()?;
    let data_dir = data_home.path().to_path_buf();

    let (server_conn, client_conn) = create_p2p_connection().await?;
    let service = Service::new(data_dir.clone(), None);
    service.set_options(Options {
        per_client_access: true,
        prompter_socket: Some(prompter.path.clone()),
    });
    server_conn
        .object_server()
        .at(
            oo7::dbus::api::Service::PATH.as_deref().unwrap(),
            service.clone(),
        )
        .await?;
    service.initialize(server_conn, Vec::new(), None, true).await?;

    // Served on the client's side as upstream's setup does: with no bus,
    // `OpenSession` asks the client for its PID, and a connection without an
    // object server never answers.
    #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
    let mock_prompter = {
        let mock_prompter = crate::tests::MockPrompterService::new();
        client_conn
            .object_server()
            .at("/org/gnome/keyring/Prompter", mock_prompter.clone())
            .await?;
        mock_prompter
    };
    #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
    let mock_prompter_plasma = {
        let mock_prompter_plasma = crate::tests::MockPrompterServicePlasma::new();
        client_conn
            .object_server()
            .at("/SecretPrompter", mock_prompter_plasma.clone())
            .await?;
        mock_prompter_plasma
    };

    let service_api = dbus::api::Service::new(&client_conn).await?;
    let (server_public_key, session) = service_api.open_session(None).await?;
    let collections = service_api.collections().await?;
    let setup = TestServiceSetup {
        server: service,
        client_conn,
        service_api,
        session: Arc::new(session),
        collections,
        server_public_key,
        keyring_secret: None,
        aes_key: None,
        #[cfg(any(feature = "gnome_native_crypto", feature = "gnome_openssl_crypto"))]
        mock_prompter,
        #[cfg(any(feature = "plasma_native_crypto", feature = "plasma_openssl_crypto"))]
        mock_prompter_plasma,
        _temp_dir: data_home,
    };
    Ok((setup, data_dir))
}

#[tokio::test]
async fn first_keyring_is_created_through_the_prompter() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([
        SocketReply::Password(""),
        SocketReply::Password("new-keyring-password"),
    ]);
    let (setup, data_dir) = setup_without_keyring(&prompter).await?;
    let keyring_file = data_dir.join("keyrings/v1/login.keyring");

    let collection = setup.default_collection().await?;
    assert!(collection.is_locked().await?);
    assert!(!keyring_file.exists());

    // An empty keyring has nothing to find: a search does not ask.
    let (unlocked, locked) = setup.service_api.search_items(&ATTRIBUTES).await?;
    assert!(unlocked.is_empty() && locked.is_empty());
    assert!(prompter.requests().is_empty());

    // The first unlock asks for a new password, not for one to check.
    let unlocked = setup
        .service_api
        .unlock(&[collection.inner().path()], None)
        .await?;
    assert_eq!(
        unlocked,
        [OwnedObjectPath::from(collection.inner().path().to_owned())]
    );
    let requests = prompter.requests();
    let types = requests
        .iter()
        .map(|r| r.json["type"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(types, ["create", "create"]);
    assert_eq!(requests[0].json["keyring"], "Login");
    assert_eq!(
        requests[1].json["warning"], "The password cannot be empty",
        "An empty password is asked again"
    );

    // The first item writes the keyring, with that password.
    let secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), Secret::text("first"));
    collection
        .create_item("First", &ATTRIBUTES, &secret, true, None)
        .await?;
    assert_eq!(prompter.requests().len(), 2, "Unlocked: nothing more asked");
    assert!(keyring_file.exists());
    let keyring =
        oo7::file::UnlockedKeyring::load(&keyring_file, Some(Secret::from("new-keyring-password")))
            .await?;
    assert_eq!(keyring.n_items().await, 1);
    assert!(
        oo7::file::UnlockedKeyring::load(&keyring_file, Some(Secret::from("another-password")))
            .await
            .is_err(),
        "Only that password opens it"
    );

    Ok(())
}

#[tokio::test]
async fn first_store_creates_the_keyring() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([SocketReply::Password("new-keyring-password")]);
    let (setup, data_dir) = setup_without_keyring(&prompter).await?;
    let keyring_file = data_dir.join("keyrings/v1/login.keyring");

    // `secret-tool store` on a fresh service: CreateItem in the locked, new
    // default keyring.
    let secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), Secret::text("first"));
    let item = setup
        .default_collection()
        .await?
        .create_item("First", &ATTRIBUTES, &secret, true, None)
        .await?;
    let requests = prompter.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].json["type"], "create");
    // The card names who stores, though the password allows no read.
    assert_eq!(requests[0].json["caller"]["bus_name"], ":p2p.test");
    assert_eq!(requests[0].pidfd_pid, Some(std::process::id()));
    assert!(requests[0].json.get("operation").is_none());
    assert!(keyring_file.exists());
    assert_eq!(item.secret(&setup.session).await?.value(), b"first");

    Ok(())
}

#[tokio::test]
async fn create_collection_names_its_caller() -> Result<(), Box<dyn std::error::Error>> {
    let prompter = MockSocketPrompter::new([SocketReply::Password("work-keyring-password")]);
    let (setup, _item) = setup_with_item(&prompter).await?;

    let collection = setup
        .service_api
        .create_collection("Work", None, None)
        .await?;
    assert_eq!(collection.label().await?, "Work");
    let requests = prompter.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].json["type"], "create");
    assert_eq!(requests[0].json["caller"]["bus_name"], ":p2p.test");
    assert_eq!(requests[0].pidfd_pid, Some(std::process::id()));
    assert!(requests[0].json.get("operation").is_none());
    Ok(())
}

#[tokio::test]
async fn dismissed_store_completes_with_a_path() -> Result<(), Box<dyn std::error::Error>> {
    use tokio_stream::StreamExt;

    let prompter = MockSocketPrompter::new([SocketReply::Deny]);
    let (setup, _data_dir) = setup_without_keyring(&prompter).await?;

    // CreateItem by hand, to see the Completed signal itself: libsecret checks
    // its result type before `dismissed`, and waits forever on an `ao`.
    let collection = setup.default_collection().await?;
    let secret = dbus::api::DBusSecret::new(Arc::clone(&setup.session), Secret::text("first"));
    let (_item, prompt_path) = collection
        .inner()
        .call_method(
            "CreateItem",
            &(
                dbus::api::Properties::for_item("First", &ATTRIBUTES),
                &secret,
                true,
            ),
        )
        .await?
        .body()
        .deserialize::<(OwnedObjectPath, OwnedObjectPath)>()?;
    let prompt = dbus::api::Prompt::new(&setup.client_conn, prompt_path)
        .await?
        .unwrap();
    let mut completed = prompt.inner().receive_signal("Completed").await?;
    prompt.prompt(None).await?;
    let message = tokio::time::timeout(tokio::time::Duration::from_secs(2), completed.next())
        .await?
        .unwrap();
    let (dismissed, result) = message
        .body()
        .deserialize::<(bool, zbus::zvariant::OwnedValue)>()?;
    assert!(dismissed);
    assert_eq!(result.value_signature(), "o", "CreateItem returns a path");

    Ok(())
}
