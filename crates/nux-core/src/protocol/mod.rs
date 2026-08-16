//! Protocole d'authentification Nux (`/nux/auth/1.0.0`).
//!
//! Phase 1 : définition des messages du handshake challenge-response et du
//! codec binaire. La logique de validation (signature, liste blanche,
//! fenêtre anti-rejeu de 5 s) arrive en Phase 2 ; les structures portent déjà
//! les champs nécessaires (`nonce`, `timestamp`) pour figer le format filaire.

mod codec;

pub use codec::{NuxCodec, MAX_MESSAGE_SIZE, decode, encode};

use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};

/// Identifiant du protocole d'authentification sur le multiplexeur.
pub const AUTH_PROTOCOL: StreamProtocol = StreamProtocol::new("/nux/auth/1.0.0");

/// Identifiant du protocole de tunneling sur le multiplexeur (Phase 3).
pub const TUNNEL_PROTOCOL: StreamProtocol = StreamProtocol::new("/nux/tunnel/1.0.0");

/// Taille d'un nonce de défi.
pub const NONCE_LEN: usize = 32;

/// Taille maximale de l'en-tête d'ouverture de tunnel sur le fil. Un nom de
/// service tient en quelques dizaines d'octets ; toute trame plus grosse est
/// un abus et le flux est abandonné.
pub const MAX_TUNNEL_HEADER_SIZE: usize = 1024;

/// Octet d'acquittement envoyé par le Guard une fois le tunnel autorisé et le
/// service local joint. En cas de refus, RIEN n'est envoyé (silence radio,
/// cadrage §3.3) : cet octet n'existe que sur le chemin du succès.
pub const TUNNEL_ACK: u8 = 0x01;

/// En-tête d'ouverture de tunnel (Phase 3), premier et unique message de
/// contrôle du flux `/nux/tunnel/1.0.0` : trame `u16` gros-boutiste
/// (longueur) suivie du bincode de cette structure, bornée à
/// [`MAX_TUNNEL_HEADER_SIZE`]. Tout ce qui suit l'acquittement du Guard est
/// relayé octet à octet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelHeader {
    /// Nom logique du service exposé par le Guard (jamais son adresse réelle,
    /// qui ne circule pas sur le réseau).
    pub service: String,
    /// Empreinte SHA-256 de l'exécutable Client (Phase 5, attestation
    /// logicielle best-effort — voir [`crate::attestation`]). Déclarée par
    /// le Client, comparée par le Guard uniquement pour les pairs auxquels
    /// il en attend une.
    pub binary_sha256: [u8; crate::attestation::SHA256_LEN],
}

/// Construit l'octet-flux canonique du challenge-response : `nonce ‖ timestamp`
/// (u64 gros-boutiste). Le Client signe exactement ces octets, le Guard
/// vérifie la signature sur exactement ces octets — toute divergence de
/// construction casserait l'authentification, d'où cette fonction unique
/// partagée par les deux rôles.
pub fn challenge_payload(nonce: &[u8; NONCE_LEN], timestamp: u64) -> [u8; NONCE_LEN + 8] {
    let mut payload = [0u8; NONCE_LEN + 8];
    payload[..NONCE_LEN].copy_from_slice(nonce);
    payload[NONCE_LEN..].copy_from_slice(&timestamp.to_be_bytes());
    payload
}

/// Requêtes émises par un nœud Client vers un Guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NuxRequest {
    /// Ouverture de session : le Guard répond par un [`NuxResponse::Challenge`].
    HandshakeInit,
    /// Réponse au défi : signature Ed25519 du nonce, accompagnée du timestamp
    /// Unix du client (rejeté au-delà de 5 s d'écart, cadrage §3.2).
    ChallengeAnswer {
        /// Signature du couple (nonce ‖ timestamp) par la clé privée du client.
        signature: Vec<u8>,
        /// Horodatage Unix (secondes) au moment de la signature.
        timestamp: u64,
    },
}

/// Réponses émises par un nœud Guard.
///
/// Volontairement laconiques : conformément au cadrage (§3.3), un échec
/// d'authentification ne produit AUCUNE réponse détaillée — le Guard coupe la
/// connexion. `Denied` n'existe que pour les refus « polis » de haut niveau
/// (ex. rôle insuffisant après une authentification pourtant valide).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NuxResponse {
    /// Défi envoyé au client : nonce unique à signer.
    Challenge {
        /// Nonce aléatoire à usage unique.
        nonce: [u8; NONCE_LEN],
        /// Horodatage Unix (secondes) d'émission du défi.
        timestamp: u64,
    },
    /// Authentification réussie ; rôles accordés au pair.
    AccessGranted {
        /// Rôles associés au `PeerId` dans la liste blanche.
        roles: Vec<String>,
    },
    /// Refus de haut niveau, sans détail exploitable par un attaquant.
    Denied,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trip() {
        let messages = [
            NuxRequest::HandshakeInit,
            NuxRequest::ChallengeAnswer {
                signature: vec![7u8; 64],
                timestamp: 1_780_000_000,
            },
        ];
        for msg in messages {
            let bytes = encode(&msg).unwrap();
            let back: NuxRequest = decode(&bytes).unwrap();
            assert_eq!(msg, back);
        }

        let resp = NuxResponse::Challenge {
            nonce: [42u8; NONCE_LEN],
            timestamp: 1_780_000_000,
        };
        let back: NuxResponse = decode(&encode(&resp).unwrap()).unwrap();
        assert_eq!(resp, back);

        let header = TunnelHeader {
            service: "postgres".into(),
            binary_sha256: [9u8; 32],
        };
        let back: TunnelHeader = decode(&encode(&header).unwrap()).unwrap();
        assert_eq!(header, back);
    }

    #[test]
    fn decode_rejects_garbage_without_panicking() {
        // Préfigure la campagne cargo-fuzz : aucun octet malformé ne doit
        // provoquer de panique, seulement une erreur propre.
        for payload in [&[][..], &[0xFF; 3], &[0x01, 0x00, 0xFE, 0xDC, 0xBA]] {
            assert!(decode::<NuxRequest>(payload).is_err());
        }
    }
}
