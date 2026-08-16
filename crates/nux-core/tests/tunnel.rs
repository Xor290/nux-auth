//! Intégration Phase 3 : tunneling TCP de bout en bout au travers de la
//! vraie pile TCP + Noise + Yamux — relais complet d'un flux applicatif,
//! autorisation par rôle de session, et silence radio face aux flux non
//! autorisés (pair sans session, service inconnu, rôle manquant).

use nux_core::{
    NuxError, NuxNode, NuxNodeBuilder, GuardAuthenticator, NodeMode, PeerId, TunnelRegistry,
    Whitelist, identity, tunnel,
};
use libp2p::Multiaddr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Service local factice : écho TCP acceptant les connexions en continu.
async fn spawn_echo_service() -> SocketAddr {
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

/// Démarre un Guard complet (auth + tunnels) et retourne son adresse et son
/// identité.
async fn spawn_guard(
    whitelist: Whitelist,
    registry: TunnelRegistry,
) -> (Multiaddr, PeerId, tokio::task::JoinHandle<()>) {
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let peer = guard.local_peer_id();
    let addr = guard.wait_for_listen_addr().await;
    let task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard
            .run_guard_with_tunnels(&mut authenticator, registry)
            .await;
    });
    (addr, peer, task)
}

/// Construit un Client connecté au Guard, sans l'authentifier.
async fn connected_client(keypair: libp2p::identity::Keypair, guard_addr: Multiaddr) -> NuxNode {
    let mut client = NuxNodeBuilder::new()
        .identity(keypair)
        .build()
        .expect("construction du Client");
    client.dial(guard_addr).expect("dial du Guard");
    client.next_connection().await.expect("connexion au Guard");
    client
}

#[tokio::test]
async fn tcp_stream_is_tunneled_end_to_end() {
    let echo = spawn_echo_service().await;

    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["db-writer"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("db-writer".into()));
    let (guard_addr, guard_peer, guard_task) = spawn_guard(whitelist, registry).await;

    let mut client = connected_client(client_keypair, guard_addr).await;
    tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification");

    // Le Client intercepte un port local et le redirige vers « echo ».
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind local");
    let local = listener.local_addr().expect("adresse locale");
    let client_task = tokio::spawn(async move {
        client
            .run_tunnel_client(
                guard_peer,
                "echo",
                listener,
                tokio_util::sync::CancellationToken::new(),
                Duration::from_secs(5),
            )
            .await;
    });

    // Un programme quelconque se connecte au port local : ses octets doivent
    // traverser Noise + Yamux, être réinjectés dans l'écho, et revenir.
    let payload = b"nux-auth phase 3";
    let mut app = tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect(local))
        .await
        .expect("connexion locale avant le délai")
        .expect("connexion au port intercepté");
    app.write_all(payload).await.expect("écriture applicative");
    let mut back = [0u8; 16];
    tokio::time::timeout(TEST_TIMEOUT, app.read_exact(&mut back))
        .await
        .expect("écho avant le délai")
        .expect("lecture de l'écho");
    assert_eq!(&back, payload);

    client_task.abort();
    guard_task.abort();
}

#[tokio::test]
async fn missing_role_is_refused_in_radio_silence() {
    let echo = spawn_echo_service().await;

    // Le pair est en liste blanche avec « reader », mais le service exige
    // « admin » : l'authentification passe, le tunnel doit être refusé.
    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["reader"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("db", echo, Some("admin".into()));
    let (guard_addr, guard_peer, guard_task) = spawn_guard(whitelist, registry).await;

    let mut client = connected_client(client_keypair, guard_addr).await;
    tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification");

    let err = tokio::time::timeout(TEST_TIMEOUT, client.open_tunnel(guard_peer, "db"))
        .await
        .expect("refus avant le délai")
        .expect_err("un rôle manquant doit être refusé");
    assert!(
        matches!(err, NuxError::AccessDenied),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}

#[tokio::test]
async fn unknown_service_is_refused_in_radio_silence() {
    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["admin"]);
    let (guard_addr, guard_peer, guard_task) = spawn_guard(whitelist, TunnelRegistry::new()).await;

    let mut client = connected_client(client_keypair, guard_addr).await;
    tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification");

    let err = tokio::time::timeout(TEST_TIMEOUT, client.open_tunnel(guard_peer, "fantome"))
        .await
        .expect("refus avant le délai")
        .expect_err("un service inconnu doit être refusé");
    assert!(
        matches!(err, NuxError::AccessDenied),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}

#[tokio::test]
async fn unauthenticated_peer_cannot_open_tunnels() {
    let echo = spawn_echo_service().await;

    // Le pair figure en liste blanche ET le service ne demande aucun rôle,
    // mais le handshake n'a pas été déroulé : aucune session, donc silence.
    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["admin"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, None);
    let (guard_addr, guard_peer, guard_task) = spawn_guard(whitelist, registry).await;

    let mut client = connected_client(client_keypair, guard_addr).await;

    let err = tokio::time::timeout(TEST_TIMEOUT, client.open_tunnel(guard_peer, "echo"))
        .await
        .expect("refus avant le délai")
        .expect_err("un pair sans session doit être refusé");
    // Coupure sèche : selon la course entre l'ouverture du flux et la
    // déconnexion imposée par le Guard, l'échec se manifeste en refus
    // d'accès ou en erreur d'ouverture — jamais en motif détaillé.
    assert!(
        matches!(
            err,
            NuxError::AccessDenied | NuxError::Tunnel(_) | NuxError::Io(_)
        ),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}

#[tokio::test]
async fn tunnel_uses_session_roles_captured_at_open_time() {
    // Deux clients, deux jeux de rôles : chaque session ne débloque que ses
    // services. Vérifie que les rôles servis sont bien ceux de la session du
    // pair appelant, pas d'un autre pair authentifié.
    let echo = spawn_echo_service().await;

    let writer_keypair = identity::generate();
    let reader_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(writer_keypair.public().to_peer_id(), ["db-writer"]);
    whitelist.allow(reader_keypair.public().to_peer_id(), ["reader"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("db", echo, Some("db-writer".into()));
    let (guard_addr, guard_peer, guard_task) = spawn_guard(whitelist, registry).await;

    let mut writer = connected_client(writer_keypair, guard_addr.clone()).await;
    tokio::time::timeout(TEST_TIMEOUT, writer.authenticate(&guard_peer))
        .await
        .expect("handshake writer avant le délai")
        .expect("authentification writer");
    let mut reader = connected_client(reader_keypair, guard_addr).await;
    tokio::time::timeout(TEST_TIMEOUT, reader.authenticate(&guard_peer))
        .await
        .expect("handshake reader avant le délai")
        .expect("authentification reader");

    // Le writer passe…
    let mut stream = tokio::time::timeout(TEST_TIMEOUT, writer.open_tunnel(guard_peer, "db"))
        .await
        .expect("ouverture avant le délai")
        .expect("le rôle db-writer doit débloquer le service");
    stream.write_all(b"ping").await.expect("écriture tunnel");
    let mut back = [0u8; 4];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut back))
        .await
        .expect("écho avant le délai")
        .expect("lecture tunnel");
    assert_eq!(&back, b"ping");

    // … le reader non, bien qu'authentifié lui aussi.
    let err = tokio::time::timeout(TEST_TIMEOUT, reader.open_tunnel(guard_peer, "db"))
        .await
        .expect("refus avant le délai")
        .expect_err("le rôle reader ne doit pas débloquer le service");
    assert!(
        matches!(err, NuxError::AccessDenied),
        "erreur reçue: {err:?}"
    );

    guard_task.abort();
}

/// L'API bas niveau (`tunnel::open` + contrôle cloné) fonctionne aussi quand
/// le swarm est piloté par une tâche indépendante — c'est le mode d'emploi
/// des intégrateurs qui gèrent leur propre boucle d'événements.
#[tokio::test]
async fn low_level_control_api_opens_tunnels() {
    let echo = spawn_echo_service().await;

    let client_keypair = identity::generate();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_keypair.public().to_peer_id(), ["ops"]);
    let mut registry = TunnelRegistry::new();
    registry.expose("echo", echo, Some("ops".into()));
    let (guard_addr, guard_peer, guard_task) = spawn_guard(whitelist, registry).await;

    let mut client = connected_client(client_keypair, guard_addr).await;
    tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("authentification");

    let mut control = client.tunnel_control();
    let client_task = tokio::spawn(async move {
        loop {
            let _ = client.next_event().await;
        }
    });

    let mut stream =
        tokio::time::timeout(TEST_TIMEOUT, tunnel::open(&mut control, guard_peer, "echo"))
            .await
            .expect("ouverture avant le délai")
            .expect("ouverture du tunnel");
    stream.write_all(b"forge").await.expect("écriture tunnel");
    let mut back = [0u8; 5];
    tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut back))
        .await
        .expect("écho avant le délai")
        .expect("lecture tunnel");
    assert_eq!(&back, b"forge");

    client_task.abort();
    guard_task.abort();
}
