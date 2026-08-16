//! Intégration Phase 2 : handshake challenge-response complet au travers de
//! la vraie pile TCP + Noise + Yamux, côté accepté (rôles restitués) et côté
//! rejeté (silence radio : coupure sans un octet d'explication).

use nux_core::{NuxError, NuxNodeBuilder, GuardAuthenticator, NodeMode, Whitelist, identity};
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Démarre un Guard adossé à la liste blanche donnée et retourne son adresse.
async fn spawn_guard(whitelist: Whitelist) -> (libp2p::Multiaddr, tokio::task::JoinHandle<()>) {
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let addr = guard.wait_for_listen_addr().await;
    let task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard.run_guard(&mut authenticator).await;
    });
    (addr, task)
}

#[tokio::test]
async fn whitelisted_client_authenticates_and_receives_roles() {
    let client_keypair = identity::generate();
    let client_peer = client_keypair.public().to_peer_id();

    let mut whitelist = Whitelist::new();
    whitelist.allow(client_peer, ["db-writer", "metrics"]);
    let (guard_addr, guard_task) = spawn_guard(whitelist).await;

    let mut client = NuxNodeBuilder::new()
        .identity(client_keypair)
        .build()
        .expect("construction du Client");
    client.dial(guard_addr).expect("dial du Guard");
    let guard_peer = client.next_connection().await.expect("connexion au Guard");

    let roles = tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("le handshake doit aboutir avant le délai")
        .expect("l'authentification doit réussir");
    assert_eq!(roles, vec!["db-writer".to_string(), "metrics".to_string()]);

    guard_task.abort();
}

#[tokio::test]
async fn unknown_client_is_cut_off_in_radio_silence() {
    // La liste blanche ne contient qu'un tiers : notre client est inconnu.
    let mut whitelist = Whitelist::new();
    whitelist.allow(identity::generate().public().to_peer_id(), ["admin"]);
    let (guard_addr, guard_task) = spawn_guard(whitelist).await;

    let mut client = NuxNodeBuilder::new()
        .build()
        .expect("construction du Client");
    client.dial(guard_addr).expect("dial du Guard");
    let guard_peer = client.next_connection().await.expect("connexion au Guard");

    let err = tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("le rejet doit être immédiat, pas un timeout")
        .expect_err("un pair hors liste blanche doit être refusé");
    // Coupure sèche, sans détail exploitable : AccessDenied et rien d'autre.
    assert!(
        matches!(err, NuxError::AccessDenied),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}

#[tokio::test]
async fn revoked_peer_cannot_reauthenticate() {
    // Le pair est admis, puis radié à chaud : la seconde authentification
    // doit échouer en silence.
    let client_keypair = identity::generate();
    let client_peer = client_keypair.public().to_peer_id();

    let mut whitelist = Whitelist::new();
    whitelist.allow(client_peer, ["reader"]);

    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_addr = guard.wait_for_listen_addr().await;

    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        let mut granted_once = false;
        loop {
            let event = guard.next_event().await;
            guard.handle_guard_event(&mut authenticator, event);
            // Dès la première session accordée, le pair est radié à chaud.
            if !granted_once && authenticator.session_roles(&client_peer).is_some() {
                authenticator.whitelist_mut().revoke(&client_peer);
                granted_once = true;
            }
        }
    });

    let mut client = NuxNodeBuilder::new()
        .identity(client_keypair)
        .build()
        .expect("construction du Client");
    client.dial(guard_addr).expect("dial du Guard");
    let guard_peer = client.next_connection().await.expect("connexion au Guard");

    let roles = tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("premier handshake avant le délai")
        .expect("la première authentification doit réussir");
    assert_eq!(roles, vec!["reader".to_string()]);

    let err = tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("second handshake avant le délai")
        .expect_err("un pair radié doit être refusé");
    assert!(
        matches!(err, NuxError::AccessDenied),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}
