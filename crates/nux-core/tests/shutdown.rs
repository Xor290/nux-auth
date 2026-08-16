//! Intégration : arrêt gracieux du Guard (`GuardControl::Shutdown`).
//!
//! - une fois l'arrêt demandé, un pair par ailleurs en liste blanche est
//!   refusé en silence (même traitement qu'un pair inconnu) ;
//! - un tunnel déjà ouvert au moment de la demande continue de fonctionner
//!   pendant le délai de grâce ;
//! - `run_guard_with_control` retourne dès que le dernier tunnel se termine,
//!   sans attendre la fin du délai de grâce (pas seulement à son expiration).

use nux_core::{
    NuxError, NuxNodeBuilder, GuardAuthenticator, GuardControl, NodeMode, TunnelRegistry,
    Whitelist, identity, tunnel,
};
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

#[tokio::test]
async fn graceful_shutdown_refuses_new_auth_but_drains_in_flight_tunnel() {
    let echo = spawn_echo_service().await;

    let active_client_keypair = identity::generate();
    let active_client_peer = active_client_keypair.public().to_peer_id();
    let late_client_keypair = identity::generate();
    let late_client_peer = late_client_keypair.public().to_peer_id();

    let mut whitelist = Whitelist::new();
    whitelist.allow(active_client_peer, ["ops"]);
    // En liste blanche dès le départ : sa demande, envoyée après l'arrêt,
    // doit tout de même être refusée — c'est le comportement spécifique à
    // l'arrêt gracieux qu'on veut prouver, pas le refus ordinaire d'un pair
    // inconnu.
    whitelist.allow(late_client_peer, ["ops"]);

    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("ops".into()));

    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_peer = guard.local_peer_id();
    let guard_addr = guard.wait_for_listen_addr().await;

    let (control_tx, control_rx) = tokio::sync::mpsc::channel(8);
    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard
            .run_guard_with_control(&mut authenticator, registry, control_rx)
            .await;
    });

    // Pair actif : authentifié et tunnel ouvert AVANT la demande d'arrêt.
    let mut active_client = NuxNodeBuilder::new()
        .identity(active_client_keypair)
        .build()
        .expect("construction du Client actif");
    active_client
        .dial(guard_addr.clone())
        .expect("dial du Guard");
    active_client
        .next_connection()
        .await
        .expect("connexion au Guard");
    tokio::time::timeout(TEST_TIMEOUT, active_client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification du pair actif");

    let mut control = active_client.tunnel_control();
    let mut stream =
        tokio::time::timeout(TEST_TIMEOUT, tunnel::open(&mut control, guard_peer, "echo"))
            .await
            .expect("ouverture de tunnel avant le délai")
            .expect("ouverture de tunnel");

    // Le swarm du Client actif doit rester piloté pour que son tunnel
    // continue de transporter des octets pendant le test.
    let active_client_task = tokio::spawn(async move {
        loop {
            active_client.next_event().await;
        }
    });

    // Démarre l'arrêt gracieux, avec un délai de grâce large : le test doit
    // le voir se terminer largement avant, pas à son expiration.
    control_tx
        .send(GuardControl::Shutdown {
            grace_period: Duration::from_secs(30),
        })
        .await
        .expect("canal de contrôle ouvert");

    // Laisse le temps à la commande d'être traitée par la boucle du Guard
    // avant de tenter la nouvelle authentification.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Un pair par ailleurs autorisé, mais qui compose APRÈS l'arrêt, doit
    // être refusé en silence — même traitement qu'un pair inconnu.
    let mut late_client = NuxNodeBuilder::new()
        .identity(late_client_keypair)
        .build()
        .expect("construction du Client tardif");
    late_client.dial(guard_addr).expect("dial du Guard");
    late_client
        .next_connection()
        .await
        .expect("connexion TCP encore acceptée");
    let err = tokio::time::timeout(TEST_TIMEOUT, late_client.authenticate(&guard_peer))
        .await
        .expect("le refus doit être immédiat, pas un timeout")
        .expect_err("un pair arrivant après l'arrêt doit être refusé malgré la liste blanche");
    assert!(
        matches!(err, NuxError::AccessDenied),
        "erreur reçue: {err:?}"
    );

    // Le tunnel déjà ouvert avant l'arrêt doit continuer de fonctionner
    // pendant le drainage.
    let payload = b"encore-actif";
    stream.write_all(payload).await.expect("écriture tunnel");
    let mut back = [0u8; 12];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut back))
        .await
        .expect("écho avant le délai")
        .expect("lecture tunnel");
    assert_eq!(&back, payload);

    // Referme le tunnel actif : le Guard doit se terminer dès que le dernier
    // tunnel se termine, bien avant le délai de grâce de 30 s.
    drop(stream);
    tokio::time::timeout(Duration::from_secs(15), guard_task)
        .await
        .expect("le Guard doit se terminer sans attendre tout le délai de grâce")
        .expect("run_guard_with_control ne doit pas paniquer");

    active_client_task.abort();
}
