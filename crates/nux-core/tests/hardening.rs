//! Intégration Phase 4 : durcissement — rate limiting des connexions
//! entrantes par IP (refus avant handshake) et résilience du client
//! (ré-authentification automatique après perte de la connexion au Guard).

use nux_core::{
    NuxNodeBuilder, GuardAuthenticator, NodeMode, TunnelRegistry, Whitelist, identity, tunnel,
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
async fn inbound_connections_are_rate_limited_per_ip() {
    // Cadence de 2 connexions par minute : la troisième depuis 127.0.0.1
    // doit être refusée avant le handshake.
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .inbound_rate_limit(2, Duration::from_secs(60))
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_addr = guard.wait_for_listen_addr().await;
    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(Whitelist::new());
        guard.run_guard(&mut authenticator).await;
    });

    // Deux connexions admises…
    let mut kept_alive = Vec::new();
    for attempt in 1..=2 {
        let mut client = NuxNodeBuilder::new().build().expect("Client");
        client.dial(guard_addr.clone()).expect("dial");
        tokio::time::timeout(TEST_TIMEOUT, client.next_connection())
            .await
            .expect("connexion avant le délai")
            .unwrap_or_else(|e| panic!("la connexion {attempt} doit être admise: {e}"));
        // La connexion doit rester établie pendant le test, sinon le swarm
        // du client la fermerait et fausserait le comptage côté Guard.
        kept_alive.push(tokio::spawn(async move {
            let mut client = client;
            loop {
                let _ = client.next_event().await;
            }
        }));
    }

    // … la troisième est coupée pendant l'établissement.
    let mut third = NuxNodeBuilder::new().build().expect("Client");
    third.dial(guard_addr).expect("dial");
    let outcome = tokio::time::timeout(TEST_TIMEOUT, third.next_connection())
        .await
        .expect("le refus doit être immédiat, pas un timeout");
    assert!(
        outcome.is_err(),
        "la troisième connexion devait être refusée, PeerId reçu: {outcome:?}"
    );

    for task in kept_alive {
        task.abort();
    }
    guard_task.abort();
}

#[tokio::test]
async fn client_reauthenticates_after_connection_loss() {
    let echo = spawn_echo_service().await;

    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["ops"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("ops".into()));

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

    // Client avec un délai d'inactivité très court : sa connexion au Guard
    // tombera d'elle-même, emportant la session côté Guard.
    let mut client = NuxNodeBuilder::new()
        .identity(client_keypair)
        .idle_timeout(Duration::from_millis(300))
        .build()
        .expect("construction du Client");
    client.dial(guard_addr.clone()).expect("dial du Guard");
    let peer = client.next_connection().await.expect("connexion au Guard");
    assert_eq!(peer, guard_peer);
    tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification initiale");

    let mut control = client.tunnel_control();
    let session_task = tokio::spawn(async move {
        client
            .run_client_session(
                guard_peer,
                guard_addr,
                tokio_util::sync::CancellationToken::new(),
                Duration::from_secs(5),
            )
            .await;
    });

    // On laisse la connexion mourir d'inactivité (300 ms) : sans la boucle
    // résiliente, la session serait close et tout tunnel refusé en silence.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // La boucle doit avoir recomposé et rejoué le handshake : un tunnel
    // finit par aboutir. On retente le temps que la reconnexion converge.
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    let mut stream = loop {
        match tunnel::open(&mut control, guard_peer, "echo").await {
            Ok(stream) => break stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("le tunnel doit aboutir après ré-authentification: {e}"),
        }
    };
    stream.write_all(b"reforge").await.expect("écriture tunnel");
    let mut back = [0u8; 7];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut back))
        .await
        .expect("écho avant le délai")
        .expect("lecture tunnel");
    assert_eq!(&back, b"reforge");

    session_task.abort();
    guard_task.abort();
}

#[tokio::test]
async fn client_reconnects_after_guard_process_restart() {
    // Contrairement au test précédent (connexion qui meurt d'inactivité
    // pendant que la tâche Guard reste en vie), ce test coupe *le listener*
    // du Guard puis en fait repartir un nouveau sur la même adresse et la
    // même identité — le dial de reconnexion échoue alors au niveau TCP
    // (`ECONNREFUSED`) le temps que le nouveau Guard démarre, chemin
    // distinct de celui déjà couvert ci-dessus (et celui qui restait bloqué
    // indéfiniment avant le correctif de `redial_known_peer` : un
    // `OutgoingConnectionError` sur dial par adresse nue porte
    // `peer_id: None`, qui ne matchait jamais le garde attendant
    // `Some(guard)` dans `authenticate()`).
    let echo = spawn_echo_service().await;
    let guard_keypair = identity::generate();
    let guard_peer = guard_keypair.public().to_peer_id();

    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["ops"]);

    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("ops".into()));
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .identity(guard_keypair.clone())
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_addr = guard.wait_for_listen_addr().await;
    let guard_task = tokio::spawn({
        let whitelist = whitelist.clone();
        async move {
            let mut authenticator = GuardAuthenticator::new(whitelist);
            guard
                .run_guard_with_tunnels(&mut authenticator, registry)
                .await;
        }
    });

    let mut client = NuxNodeBuilder::new()
        .identity(client_keypair)
        .build()
        .expect("construction du Client");
    client.dial(guard_addr.clone()).expect("dial du Guard");
    let peer = client.next_connection().await.expect("connexion au Guard");
    assert_eq!(peer, guard_peer);
    tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification initiale");

    let mut control = client.tunnel_control();
    let session_addr = guard_addr.clone();
    let session_task = tokio::spawn(async move {
        client
            .run_client_session(
                guard_peer,
                session_addr,
                tokio_util::sync::CancellationToken::new(),
                Duration::from_secs(5),
            )
            .await;
    });

    // Coupe le listener : le port n'accepte plus rien, tout redial échoue
    // désormais au niveau TCP (`ECONNREFUSED`), pas par simple coupure d'une
    // connexion déjà établie.
    guard_task.abort();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Repart sur la même adresse et la même identité, pour que le Client
    // (qui redial `guard_addr` en ciblant `guard_peer`) retrouve le même pair.
    let echo2 = spawn_echo_service().await;
    let mut registry2 = TunnelRegistry::new();
    registry2.expose("echo", echo2, Some("ops".into()));
    let mut guard2 = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .identity(guard_keypair)
        .listen_on(guard_addr)
        .build()
        .expect("construction du second Guard");
    let guard2_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard2
            .run_guard_with_tunnels(&mut authenticator, registry2)
            .await;
    });

    // Laisse `run_client_session` reconverger seul avant de solliciter le
    // tunnel : `tunnel::open`/`Control::open_stream` compose lui-même un
    // pair non connecté, et le faire concurremment à `reauthenticate()`
    // provoquerait un double dial vers le même pair — sans rapport avec ce
    // que ce test vérifie.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // La boucle de reconnexion doit converger sans intervention : on retente
    // l'ouverture d'un tunnel jusqu'à ce que le nouveau Guard réponde.
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    let mut stream = loop {
        match tunnel::open(&mut control, guard_peer, "echo").await {
            Ok(stream) => break stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("le tunnel doit aboutir après redémarrage du Guard: {e}"),
        }
    };
    stream.write_all(b"reborn").await.expect("écriture tunnel");
    let mut back = [0u8; 6];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut back))
        .await
        .expect("écho avant le délai")
        .expect("lecture tunnel");
    assert_eq!(&back, b"reborn");

    session_task.abort();
    guard2_task.abort();
}
