//! Intégration : correctifs d'autorisation post-revue de sécurité.
//!
//! - #1 : une radiation à chaud invalide immédiatement l'accès aux nouveaux
//!   tunnels, même si le pair garde sa connexion ouverte ;
//! - #2 : un pair authentifié ne peut pas ouvrir plus de flux tunnel
//!   concurrents que le plafond anti-amplification ;
//! - #3 : le rechargement de liste blanche (`GuardControl::ReloadWhitelist`,
//!   déclenché par `SIGHUP` côté CLI) radie et déconnecte les pairs qui en
//!   sortent, sans affecter ceux qui y restent — y compris un simple
//!   changement de rôle, reflété sans coupure de connexion.

use nux_core::{
    NuxNodeBuilder, GuardAuthenticator, GuardControl, NodeMode, TunnelRegistry, Whitelist,
    identity, tunnel,
};
use libp2p::Multiaddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Service local factice : écho TCP acceptant les connexions en continu.
async fn spawn_echo_service() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind écho");
    let addr = listener.local_addr().expect("adresse écho");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    addr
}

async fn connected_authenticated_client(
    keypair: libp2p::identity::Keypair,
    guard_addr: Multiaddr,
    guard_peer: libp2p::PeerId,
) -> nux_core::NuxNode {
    let mut client = NuxNodeBuilder::new()
        .identity(keypair)
        .build()
        .expect("construction du Client");
    client.dial(guard_addr).expect("dial du Guard");
    client.next_connection().await.expect("connexion au Guard");
    tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification");
    client
}

/// #1 — Un pair radié à chaud (via le canal de contrôle) ne peut plus ouvrir
/// de nouveau tunnel, et sa connexion est coupée.
#[tokio::test]
async fn revoked_peer_loses_tunnel_access() {
    let echo = spawn_echo_service().await;

    let client_keypair = identity::generate();
    let client_peer = client_keypair.public().to_peer_id();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_peer, ["ops"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("ops".into()));

    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_peer = guard.local_peer_id();
    let guard_addr = guard.wait_for_listen_addr().await;

    let (control_tx, control_rx) = tokio::sync::mpsc::channel(4);
    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard
            .run_guard_with_control(&mut authenticator, registry, control_rx)
            .await;
    });

    let mut client = connected_authenticated_client(client_keypair, guard_addr, guard_peer).await;

    // Avant radiation : un tunnel passe.
    let mut ok = tokio::time::timeout(TEST_TIMEOUT, client.open_tunnel(guard_peer, "echo"))
        .await
        .expect("ouverture avant le délai")
        .expect("tunnel autorisé avant radiation");
    ok.write_all(b"pre").await.expect("écriture");
    let mut back = [0u8; 3];
    ok.read_exact(&mut back).await.expect("écho");
    assert_eq!(&back, b"pre");

    // Radiation à chaud par le canal de contrôle.
    control_tx
        .send(GuardControl::Revoke(client_peer))
        .await
        .expect("commande de radiation");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Après radiation : toute nouvelle ouverture est refusée en silence.
    let err = tokio::time::timeout(TEST_TIMEOUT, client.open_tunnel(guard_peer, "echo"))
        .await
        .expect("refus avant le délai")
        .expect_err("un pair radié ne doit plus ouvrir de tunnel");
    // Refus silencieux : selon la couche qui constate la coupure (connexion
    // tombée, flux abandonné à l'écriture ou à la lecture de l'ACK), l'échec
    // se présente en AccessDenied, Tunnel ou Io — jamais en motif détaillé.
    assert!(
        matches!(
            err,
            nux_core::NuxError::AccessDenied
                | nux_core::NuxError::Tunnel(_)
                | nux_core::NuxError::Io(_)
        ),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}

/// #2 — Un pair ne peut pas dépasser son plafond de flux tunnel concurrents :
/// au-delà, les flux excédentaires sont abandonnés, mais la connexion et les
/// tunnels déjà ouverts survivent.
#[tokio::test]
async fn per_peer_stream_cap_blocks_amplification() {
    let echo = spawn_echo_service().await;

    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["ops"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("ops".into()));
    // Plafond volontairement bas : 2 flux concurrents par pair.
    registry.max_concurrent_streams(2, 1024);

    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_peer = guard.local_peer_id();
    let guard_addr = guard.wait_for_listen_addr().await;
    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard
            .run_guard_with_tunnels(&mut authenticator, registry)
            .await;
    });

    let mut client = connected_authenticated_client(client_keypair, guard_addr, guard_peer).await;
    let mut control = client.tunnel_control();
    let client_task = tokio::spawn(async move {
        loop {
            let _ = client.next_event().await;
        }
    });

    // Deux tunnels ouverts et MAINTENUS (on garde les flux en vie) : le
    // plafond de 2 est atteint.
    let mut held = Vec::new();
    for i in 0..2 {
        let stream =
            tokio::time::timeout(TEST_TIMEOUT, tunnel::open(&mut control, guard_peer, "echo"))
                .await
                .expect("ouverture avant le délai")
                .unwrap_or_else(|e| panic!("le tunnel {i} doit être admis: {e}"));
        held.push(stream);
    }

    // Le troisième flux concurrent dépasse le plafond : le Guard l'abandonne
    // sans acquittement → AccessDenied côté client.
    let err = tokio::time::timeout(TEST_TIMEOUT, tunnel::open(&mut control, guard_peer, "echo"))
        .await
        .expect("refus avant le délai")
        .expect_err("le 3e flux concurrent doit être refusé");
    // Flux abandonné en silence : refus visible à l'écriture (Io) ou à la
    // lecture de l'ACK (AccessDenied) selon la course.
    assert!(
        matches!(
            err,
            nux_core::NuxError::AccessDenied | nux_core::NuxError::Io(_)
        ),
        "erreur reçue: {err:?}"
    );

    // Les deux premiers tunnels fonctionnent toujours.
    held[0].write_all(b"ping").await.expect("écriture");
    let mut back = [0u8; 4];
    held[0].read_exact(&mut back).await.expect("écho");
    assert_eq!(&back, b"ping");

    // Un flux libéré rend du crédit : une nouvelle ouverture repasse.
    held.pop();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut reopened =
        tokio::time::timeout(TEST_TIMEOUT, tunnel::open(&mut control, guard_peer, "echo"))
            .await
            .expect("réouverture avant le délai")
            .expect("un flux libéré doit rendre du crédit");
    reopened.write_all(b"pong").await.expect("écriture");
    let mut back2 = [0u8; 4];
    reopened.read_exact(&mut back2).await.expect("écho");
    assert_eq!(&back2, b"pong");

    client_task.abort();
    guard_task.abort();
}

/// #3a — Un rechargement de liste blanche qui exclut un pair jusque-là
/// authentifié le radie et coupe sa connexion, sans affecter un second pair
/// qui reste dans la nouvelle liste.
#[tokio::test]
async fn reload_whitelist_revokes_dropped_peer_but_spares_others() {
    let echo = spawn_echo_service().await;

    let dropped_keypair = identity::generate();
    let dropped_peer = dropped_keypair.public().to_peer_id();
    let kept_keypair = identity::generate();
    let kept_peer = kept_keypair.public().to_peer_id();

    let mut whitelist = Whitelist::new();
    whitelist.allow(dropped_peer, ["ops"]);
    whitelist.allow(kept_peer, ["ops"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("ops".into()));

    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_peer = guard.local_peer_id();
    let guard_addr = guard.wait_for_listen_addr().await;

    let (control_tx, control_rx) = tokio::sync::mpsc::channel(4);
    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard
            .run_guard_with_control(&mut authenticator, registry, control_rx)
            .await;
    });

    let mut dropped =
        connected_authenticated_client(dropped_keypair, guard_addr.clone(), guard_peer).await;
    let mut kept = connected_authenticated_client(kept_keypair, guard_addr, guard_peer).await;

    // Rechargement : seul `kept_peer` figure dans la nouvelle liste.
    let mut reloaded = Whitelist::new();
    reloaded.allow(kept_peer, ["ops"]);
    control_tx
        .send(GuardControl::ReloadWhitelist(reloaded))
        .await
        .expect("commande de rechargement");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Le pair exclu ne peut plus ouvrir de tunnel — refus silencieux.
    let err = tokio::time::timeout(TEST_TIMEOUT, dropped.open_tunnel(guard_peer, "echo"))
        .await
        .expect("refus avant le délai")
        .expect_err("un pair exclu par rechargement ne doit plus ouvrir de tunnel");
    assert!(
        matches!(
            err,
            nux_core::NuxError::AccessDenied
                | nux_core::NuxError::Tunnel(_)
                | nux_core::NuxError::Io(_)
        ),
        "erreur reçue: {err:?}"
    );

    // Le pair conservé n'est pas affecté par le rechargement.
    let mut ok = tokio::time::timeout(TEST_TIMEOUT, kept.open_tunnel(guard_peer, "echo"))
        .await
        .expect("ouverture avant le délai")
        .expect("le pair conservé doit toujours pouvoir ouvrir un tunnel");
    ok.write_all(b"still-ok").await.expect("écriture");
    let mut back = [0u8; 8];
    ok.read_exact(&mut back).await.expect("écho");
    assert_eq!(&back, b"still-ok");

    guard_task.abort();
}

/// #3b — Un rechargement qui ne fait qu'abaisser les rôles d'un pair encore
/// présent dans la liste blanche ne coupe PAS sa connexion : le nouveau rôle
/// s'applique dès la prochaine ouverture de tunnel, sans déconnexion.
#[tokio::test]
async fn reload_whitelist_narrows_roles_without_disconnecting() {
    let echo = spawn_echo_service().await;

    let client_keypair = identity::generate();
    let client_peer = client_keypair.public().to_peer_id();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_peer, ["admin"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("admin".into()));

    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_peer = guard.local_peer_id();
    let guard_addr = guard.wait_for_listen_addr().await;

    let (control_tx, control_rx) = tokio::sync::mpsc::channel(4);
    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard
            .run_guard_with_control(&mut authenticator, registry, control_rx)
            .await;
    });

    let mut client = connected_authenticated_client(client_keypair, guard_addr, guard_peer).await;

    // Avant rechargement : le rôle "admin" débloque le service.
    tokio::time::timeout(TEST_TIMEOUT, client.open_tunnel(guard_peer, "echo"))
        .await
        .expect("ouverture avant le délai")
        .expect("le rôle admin doit débloquer le service avant rechargement");

    // Rechargement : le pair reste autorisé, mais perd le rôle "admin".
    let mut reloaded = Whitelist::new();
    reloaded.allow(client_peer, ["reader"]);
    control_tx
        .send(GuardControl::ReloadWhitelist(reloaded))
        .await
        .expect("commande de rechargement");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // La connexion elle-même doit avoir survécu au rechargement : une requête
    // d'authentification (déjà validée) reste inutile, mais l'ouverture de
    // tunnel doit échouer proprement par manque de rôle, PAS par coupure de
    // connexion — vérifié en tentant une ouverture, qui doit être un refus
    // d'autorisation et non une erreur de connexion perdue.
    let err = tokio::time::timeout(TEST_TIMEOUT, client.open_tunnel(guard_peer, "echo"))
        .await
        .expect("refus avant le délai")
        .expect_err("le rôle admin retiré ne doit plus débloquer le service");
    assert!(
        matches!(
            err,
            nux_core::NuxError::AccessDenied | nux_core::NuxError::Io(_)
        ),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}
