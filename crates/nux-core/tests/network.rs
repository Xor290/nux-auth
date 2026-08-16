//! Test d'intégration réseau (cadrage §4) : un réseau local complet est
//! instancié en mémoire de test — un Guard qui écoute, un Client qui compose —
//! et un aller-retour complet du protocole d'authentification est validé au
//! travers de la vraie pile TCP + Noise + Yamux.

use nux_core::protocol::{NuxRequest, NuxResponse, NONCE_LEN};
use nux_core::{NuxBehaviourEvent, NuxNode, NuxNodeBuilder, NodeMode, PeerId, SwarmEvent};
use libp2p::request_response::{Event as ReqRespEvent, Message};
use std::time::Duration;

fn expected_challenge() -> NuxResponse {
    NuxResponse::Challenge {
        nonce: [0xA5; NONCE_LEN],
        timestamp: 1_780_000_000,
    }
}

/// Pilote le Guard : répond à chaque `HandshakeInit` par un défi fixe.
async fn drive_guard(mut guard: NuxNode) {
    loop {
        if let SwarmEvent::Behaviour(NuxBehaviourEvent::Auth(ReqRespEvent::Message {
            message: Message::Request {
                request, channel, ..
            },
            ..
        })) = guard.next_event().await
        {
            assert_eq!(request, NuxRequest::HandshakeInit);
            guard
                .send_response(channel, expected_challenge())
                .expect("le canal de réponse doit être ouvert");
        }
    }
}

/// Pilote le Client jusqu'à réception de la réponse du Guard.
async fn drive_client(mut client: NuxNode, guard_peer: PeerId) -> NuxResponse {
    loop {
        match client.next_event().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == guard_peer => {
                client.send_request(&guard_peer, NuxRequest::HandshakeInit);
            }
            SwarmEvent::Behaviour(NuxBehaviourEvent::Auth(ReqRespEvent::Message {
                peer,
                message: Message::Response { response, .. },
                ..
            })) => {
                assert_eq!(peer, guard_peer);
                return response;
            }
            SwarmEvent::Behaviour(NuxBehaviourEvent::Auth(ReqRespEvent::OutboundFailure {
                error,
                ..
            })) => panic!("échec de la requête sortante: {error}"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn handshake_round_trip_over_tcp_noise_yamux() {
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr valide"))
        .build()
        .expect("construction du Guard");
    let guard_peer = guard.local_peer_id();
    let guard_addr = guard.wait_for_listen_addr().await;

    let mut client = NuxNodeBuilder::new()
        .mode(NodeMode::Client)
        .build()
        .expect("construction du Client");
    assert_eq!(client.mode(), NodeMode::Client);
    client.dial(guard_addr).expect("dial du Guard");

    let guard_task = tokio::spawn(drive_guard(guard));

    let response = tokio::time::timeout(Duration::from_secs(10), drive_client(client, guard_peer))
        .await
        .expect("le handshake doit aboutir avant le délai");
    assert_eq!(response, expected_challenge());

    guard_task.abort();
}

#[tokio::test]
async fn handshake_round_trip_over_quic() {
    let mut guard = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .listen_on(
            "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("multiaddr valide"),
        )
        .build()
        .expect("construction du Guard");
    let guard_peer = guard.local_peer_id();
    let guard_addr = guard.wait_for_listen_addr().await;

    let mut client = NuxNodeBuilder::new()
        .mode(NodeMode::Client)
        .build()
        .expect("construction du Client");
    client.dial(guard_addr).expect("dial du Guard");

    let guard_task = tokio::spawn(drive_guard(guard));

    let response = tokio::time::timeout(Duration::from_secs(10), drive_client(client, guard_peer))
        .await
        .expect("le handshake doit aboutir avant le délai");
    assert_eq!(response, expected_challenge());

    guard_task.abort();
}

#[tokio::test]
async fn nodes_have_distinct_ephemeral_identities() {
    let a = NuxNodeBuilder::new().build().expect("nœud A");
    let b = NuxNodeBuilder::new().build().expect("nœud B");
    assert_ne!(a.local_peer_id(), b.local_peer_id());
}
