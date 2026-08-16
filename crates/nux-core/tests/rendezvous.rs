//! Intégration découverte de pairs : un Guard réserve un circuit relay puis
//! s'enregistre sous un namespace auprès du même point de rendezvous ; un
//! Client résout ce namespace, compose le pair découvert au travers du
//! circuit, et authentifie — sans jamais connaître l'adresse du Guard à
//! l'avance.

use nux_core::{NuxNodeBuilder, GuardAuthenticator, Namespace, NodeMode, Whitelist, identity};
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, SwarmBuilder, noise, relay, rendezvous, tcp, yamux};
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(libp2p::swarm::NetworkBehaviour)]
struct RendezvousServerBehaviour {
    relay: relay::Behaviour,
    rendezvous: rendezvous::server::Behaviour,
}

/// Serveur combinant relay et rendezvous, miroir en mémoire de `nodes_relay`
/// (qui compose les deux comportements sur le même nœud).
async fn spawn_server() -> (PeerId, Multiaddr) {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("transport tcp")
        .with_behaviour(|key| RendezvousServerBehaviour {
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()),
            rendezvous: rendezvous::server::Behaviour::new(rendezvous::server::Config::default()),
        })
        .expect("comportement relay + rendezvous")
        .build();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .expect("écoute du serveur");
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    // Comme dans tests/relay.rs : sans `identify`, le serveur n'a aucune
    // adresse externe confirmée par observation — on l'enregistre
    // directement (équivalent à une adresse confirmée en production).
    swarm.add_external_address(addr.clone());
    let peer_id = *swarm.local_peer_id();
    tokio::spawn(async move {
        loop {
            swarm.select_next_some().await;
        }
    });
    (peer_id, addr)
}

#[tokio::test]
async fn discovery_resolves_namespace_to_authenticated_guard() {
    let (server_peer, server_addr) = spawn_server().await;
    let server_addr = server_addr.with(Protocol::P2p(server_peer));

    let client_keypair = identity::generate();
    let client_peer = client_keypair.public().to_peer_id();
    let mut whitelist = Whitelist::new();
    whitelist.allow(client_peer, ["ops"]);

    let guard_keypair = identity::generate();
    let guard_peer = guard_keypair.public().to_peer_id();
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .identity(guard_keypair)
        .build()
        .expect("construction du Guard");

    // Le Guard doit être connecté au serveur avant de réserver un circuit ou
    // de s'enregistrer : les deux transitent par cette même connexion.
    guard.dial(server_addr.clone()).expect("dial du serveur");
    let connected = tokio::time::timeout(TEST_TIMEOUT, guard.next_connection())
        .await
        .expect("connexion au serveur avant le délai")
        .expect("connexion au serveur");
    assert_eq!(connected, server_peer);

    guard
        .listen_on(server_addr.clone().with(Protocol::P2pCircuit))
        .expect("demande de réservation de circuit");
    tokio::time::timeout(
        TEST_TIMEOUT,
        guard.wait_for_circuit_reservation(server_peer),
    )
    .await
    .expect("réservation de circuit acceptée avant le délai")
    .expect("réservation de circuit acceptée");

    let namespace = Namespace::new("prod-db".to_string()).expect("namespace valide");
    tokio::time::timeout(
        TEST_TIMEOUT,
        guard.register_namespace(server_peer, namespace.clone()),
    )
    .await
    .expect("enregistrement rendezvous avant le délai")
    .expect("enregistrement rendezvous accepté");

    let guard_task = tokio::spawn(async move {
        let mut authenticator = GuardAuthenticator::new(whitelist);
        guard.run_guard(&mut authenticator).await;
    });

    let mut client = NuxNodeBuilder::new()
        .identity(client_keypair)
        .build()
        .expect("construction du Client");
    client.dial(server_addr.clone()).expect("dial du serveur");
    tokio::time::timeout(TEST_TIMEOUT, client.wait_for_peer(server_peer))
        .await
        .expect("connexion au serveur avant le délai")
        .expect("connexion au serveur");

    let (discovered_peer, _addr) = tokio::time::timeout(
        TEST_TIMEOUT,
        client.discover_and_dial(server_peer, namespace),
    )
    .await
    .expect("découverte avant le délai")
    .expect("un Guard doit être découvert et joignable");
    assert_eq!(discovered_peer, guard_peer);

    let roles = tokio::time::timeout(TEST_TIMEOUT, client.authenticate(&guard_peer))
        .await
        .expect("handshake avant le délai")
        .expect("l'authentification doit réussir après découverte");
    assert_eq!(roles, vec!["ops".to_string()]);

    guard_task.abort();
}
