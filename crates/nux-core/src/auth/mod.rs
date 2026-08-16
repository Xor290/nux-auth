//! Logique d'authentification challenge-response (cadrage §2.1, §3.2, §3.3).
//!
//! Déroulé nominal :
//! 1. le Client envoie `HandshakeInit` ;
//! 2. le Guard vérifie que le `PeerId` figure en liste blanche (consultation
//!    en temps constant) et répond par un défi : nonce aléatoire à usage
//!    unique ;
//! 3. le Client signe `nonce ‖ timestamp` avec sa clé privée Ed25519 et
//!    renvoie `ChallengeAnswer` ;
//! 4. le Guard consomme le défi, contrôle la fenêtre anti-rejeu de
//!    [`MAX_CLOCK_SKEW_SECS`] secondes, vérifie la signature contre la clé
//!    publique incluse dans le `PeerId`, et accorde les rôles.
//!
//! Tout échec produit [`AuthOutcome::Reject`] : l'appelant coupe alors la
//! connexion **sans émettre un octet** — le motif du refus ne quitte jamais
//! le nœud (journal local uniquement).

mod whitelist;

pub use whitelist::Whitelist;

use crate::error::{NuxError, Result};
use crate::protocol::{NuxRequest, NuxResponse, NONCE_LEN, challenge_payload};
use libp2p::PeerId;
use libp2p::identity::{Keypair, PublicKey};
use rand::RngCore;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Écart maximal toléré entre l'horloge locale du Guard et le timestamp d'un
/// paquet d'authentification — c'est aussi la durée de vie d'un défi émis
/// (cadrage §3.2 : 5 secondes).
pub const MAX_CLOCK_SKEW_SECS: u64 = 5;

/// Horloge Unix locale, en secondes.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Décision du Guard à l'issue d'une vérification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Pair authentifié ; rôles à lui accorder.
    Granted {
        /// Rôles issus de la liste blanche.
        roles: Vec<String>,
    },
    /// Échec. Le motif n'est JAMAIS transmis au pair (silence radio, cadrage
    /// §3.3) : il est journalisé localement et la connexion doit être coupée.
    Reject,
}

/// Défi émis, en attente de réponse. À usage strictement unique.
struct IssuedChallenge {
    nonce: [u8; NONCE_LEN],
    issued_at: u64,
}

/// Autorité d'authentification d'un nœud Guard : détient la liste blanche,
/// les défis en cours et les sessions authentifiées.
///
/// La table des défis en attente est bornée par construction : seuls les
/// pairs en liste blanche peuvent y créer une entrée, à raison d'une seule
/// par pair (un nouveau défi remplace le précédent).
pub struct GuardAuthenticator {
    whitelist: Whitelist,
    pending: HashMap<PeerId, IssuedChallenge>,
    sessions: HashMap<PeerId, Vec<String>>,
}

impl GuardAuthenticator {
    /// Nouvelle autorité adossée à la liste blanche donnée.
    pub fn new(whitelist: Whitelist) -> Self {
        Self {
            whitelist,
            pending: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// Émet un défi pour `peer`, ou `None` si le pair n'est pas en liste
    /// blanche — l'appelant doit alors couper la connexion sans répondre.
    pub fn issue(&mut self, peer: PeerId) -> Option<NuxResponse> {
        self.issue_at(peer, unix_now())
    }

    fn issue_at(&mut self, peer: PeerId, now: u64) -> Option<NuxResponse> {
        if self.whitelist.roles(&peer).is_none() {
            debug!(%peer, "pair hors liste blanche: aucun défi émis");
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.pending.insert(
            peer,
            IssuedChallenge {
                nonce,
                issued_at: now,
            },
        );
        Some(NuxResponse::Challenge {
            nonce,
            timestamp: now,
        })
    }

    /// Vérifie la réponse à un défi. Toute anomalie — défi absent ou expiré,
    /// horodatage hors fenêtre, pair radié, signature invalide — produit un
    /// [`AuthOutcome::Reject`] sans distinction observable par le pair.
    pub fn verify(&mut self, peer: &PeerId, signature: &[u8], timestamp: u64) -> AuthOutcome {
        self.verify_at(peer, signature, timestamp, unix_now())
    }

    fn verify_at(
        &mut self,
        peer: &PeerId,
        signature: &[u8],
        timestamp: u64,
        now: u64,
    ) -> AuthOutcome {
        // Défi à usage unique : consommé immédiatement, que la vérification
        // aboutisse ou non — une signature interceptée ne peut être rejouée.
        let Some(challenge) = self.pending.remove(peer) else {
            debug!(%peer, "réponse sans défi en attente");
            return AuthOutcome::Reject;
        };
        if now.saturating_sub(challenge.issued_at) > MAX_CLOCK_SKEW_SECS {
            debug!(%peer, "défi expiré");
            return AuthOutcome::Reject;
        }
        if now.abs_diff(timestamp) > MAX_CLOCK_SKEW_SECS {
            debug!(%peer, "horodatage hors de la fenêtre anti-rejeu");
            return AuthOutcome::Reject;
        }
        // Re-consultation de la liste blanche : le pair peut avoir été radié
        // entre l'émission du défi et la réponse.
        let Some(roles) = self.whitelist.roles(peer) else {
            debug!(%peer, "pair radié de la liste blanche");
            return AuthOutcome::Reject;
        };
        let Some(public) = public_key_of(peer) else {
            debug!(%peer, "clé publique inextractible du PeerId");
            return AuthOutcome::Reject;
        };
        let payload = challenge_payload(&challenge.nonce, timestamp);
        if !public.verify(&payload, signature) {
            debug!(%peer, "signature invalide");
            return AuthOutcome::Reject;
        }
        self.sessions.insert(*peer, roles.clone());
        AuthOutcome::Granted { roles }
    }

    /// Rôles effectifs d'un pair authentifié, ou `None` s'il n'a pas de
    /// session **ou** s'il a été radié depuis. C'est ce que consulte le
    /// tunneling (Phase 3) avant de relayer un flux.
    ///
    /// Point critique : les rôles retournés sont ceux de la liste blanche
    /// *à l'instant de l'appel*, pas ceux figés à l'authentification. Une
    /// radiation à chaud prend donc effet immédiatement sur les nouveaux
    /// flux — sans quoi un pair radié gardant sa connexion ouverte
    /// continuerait d'ouvrir des tunnels (contournement d'autorisation).
    /// Une modification de rôle (rehaussement/abaissement) se reflète de la
    /// même façon.
    pub fn session_roles(&self, peer: &PeerId) -> Option<Vec<String>> {
        // Une session ne suffit pas : le pair doit être ENCORE en liste
        // blanche. On retourne les rôles courants de la liste, autoritaires.
        if !self.sessions.contains_key(peer) {
            return None;
        }
        self.whitelist.roles(peer)
    }

    /// Radiation autoritaire d'un pair : le retire de la liste blanche, clôt
    /// sa session et invalide tout défi en attente. Retourne `true` si le
    /// pair avait une session active — l'appelant doit alors couper sa
    /// connexion ([`crate::NuxNode::disconnect`]) pour interrompre les
    /// tunnels déjà en cours de relais, que ce contrôle logique ne peut
    /// arrêter à lui seul.
    pub fn revoke(&mut self, peer: &PeerId) -> bool {
        self.whitelist.revoke(peer);
        self.pending.remove(peer);
        let had_session = self.sessions.remove(peer).is_some();
        if had_session {
            debug!(%peer, "pair radié: session close");
        }
        had_session
    }

    /// Clôt la session d'un pair (à appeler à la déconnexion) et invalide
    /// tout défi encore en attente pour lui.
    pub fn end_session(&mut self, peer: &PeerId) {
        self.pending.remove(peer);
        if self.sessions.remove(peer).is_some() {
            debug!(%peer, "session close");
        }
    }

    /// Accès mutable à la liste blanche (ajouts, ou radiations dont on gère
    /// soi-même la coupure de session). Pour une radiation sûre en une
    /// étape, préférer [`GuardAuthenticator::revoke`].
    pub fn whitelist_mut(&mut self) -> &mut Whitelist {
        &mut self.whitelist
    }

    /// Pairs actuellement authentifiés (session active). Sert au
    /// rechargement de configuration
    /// ([`crate::GuardControl::ReloadWhitelist`]) pour déterminer qui perd
    /// l'accès sous la nouvelle liste blanche, sans devoir déjà la comparer
    /// entrée par entrée à la précédente.
    pub fn authenticated_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.sessions.keys().copied()
    }
}

/// Côté Client : construit la réponse signée à un défi reçu. La signature
/// couvre `nonce ‖ timestamp` — le timestamp est celui du Client, au moment
/// de la signature, contrôlé par le Guard dans sa fenêtre anti-rejeu.
pub fn answer_challenge(keypair: &Keypair, nonce: &[u8; NONCE_LEN]) -> Result<NuxRequest> {
    let timestamp = unix_now();
    let payload = challenge_payload(nonce, timestamp);
    let signature = keypair
        .sign(&payload)
        .map_err(|e| NuxError::Identity(format!("échec de signature: {e}")))?;
    Ok(NuxRequest::ChallengeAnswer {
        signature,
        timestamp,
    })
}

/// Extrait la clé publique incluse dans un `PeerId`. Toujours possible pour
/// Ed25519 : la clé (32 octets) est inlinée dans le multihash `identity`.
fn public_key_of(peer: &PeerId) -> Option<PublicKey> {
    const IDENTITY_MULTIHASH_CODE: u64 = 0x00;
    let multihash = peer.as_ref();
    (multihash.code() == IDENTITY_MULTIHASH_CODE)
        .then(|| PublicKey::try_decode_protobuf(multihash.digest()).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    const T0: u64 = 1_780_000_000;

    fn setup(roles: &[&str]) -> (GuardAuthenticator, Keypair, PeerId) {
        let client = identity::generate();
        let peer = client.public().to_peer_id();
        let mut whitelist = Whitelist::new();
        whitelist.allow(peer, roles.iter().copied());
        (GuardAuthenticator::new(whitelist), client, peer)
    }

    fn nonce_of(response: &NuxResponse) -> [u8; NONCE_LEN] {
        match response {
            NuxResponse::Challenge { nonce, .. } => *nonce,
            other => panic!("défi attendu, reçu {other:?}"),
        }
    }

    fn sign(keypair: &Keypair, nonce: &[u8; NONCE_LEN], timestamp: u64) -> Vec<u8> {
        keypair.sign(&challenge_payload(nonce, timestamp)).unwrap()
    }

    #[test]
    fn valid_answer_is_granted_with_roles() {
        let (mut guard, client, peer) = setup(&["db-writer", "metrics"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        let outcome = guard.verify_at(&peer, &sign(&client, &nonce, T0 + 2), T0 + 2, T0 + 3);
        assert_eq!(
            outcome,
            AuthOutcome::Granted {
                roles: vec!["db-writer".into(), "metrics".into()]
            }
        );
        assert_eq!(
            guard.session_roles(&peer),
            Some(vec!["db-writer".to_string(), "metrics".to_string()])
        );
    }

    #[test]
    fn challenge_is_single_use() {
        let (mut guard, client, peer) = setup(&["r"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        let signature = sign(&client, &nonce, T0);
        assert!(matches!(
            guard.verify_at(&peer, &signature, T0, T0),
            AuthOutcome::Granted { .. }
        ));
        // Rejeu de la même signature valide : le défi a été consommé.
        assert_eq!(
            guard.verify_at(&peer, &signature, T0, T0),
            AuthOutcome::Reject
        );
    }

    #[test]
    fn unknown_peer_gets_no_challenge() {
        let (mut guard, _, _) = setup(&["r"]);
        let stranger = identity::generate().public().to_peer_id();
        assert!(guard.issue_at(stranger, T0).is_none());
    }

    #[test]
    fn timestamp_outside_replay_window_is_rejected() {
        // Timestamp trop vieux (écart de 6 s > 5 s).
        let (mut guard, client, peer) = setup(&["r"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        assert_eq!(
            guard.verify_at(&peer, &sign(&client, &nonce, T0 - 2), T0 - 2, T0 + 4),
            AuthOutcome::Reject
        );

        // Timestamp dans le futur (écart de 6 s > 5 s).
        let (mut guard, client, peer) = setup(&["r"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        assert_eq!(
            guard.verify_at(&peer, &sign(&client, &nonce, T0 + 6), T0 + 6, T0),
            AuthOutcome::Reject
        );

        // Borne exacte : 5 s d'écart, encore accepté.
        let (mut guard, client, peer) = setup(&["r"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        assert!(matches!(
            guard.verify_at(&peer, &sign(&client, &nonce, T0 + 5), T0 + 5, T0),
            AuthOutcome::Granted { .. }
        ));
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let (mut guard, client, peer) = setup(&["r"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        let now = T0 + MAX_CLOCK_SKEW_SECS + 1;
        assert_eq!(
            guard.verify_at(&peer, &sign(&client, &nonce, now), now, now),
            AuthOutcome::Reject
        );
    }

    #[test]
    fn forged_signature_is_rejected() {
        let (mut guard, _, peer) = setup(&["r"]);
        let impostor = identity::generate();
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        assert_eq!(
            guard.verify_at(&peer, &sign(&impostor, &nonce, T0), T0, T0),
            AuthOutcome::Reject
        );
        assert_eq!(guard.session_roles(&peer), None);
    }

    #[test]
    fn old_signature_does_not_cover_new_nonce() {
        let (mut guard, client, peer) = setup(&["r"]);
        let first_nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        let old_signature = sign(&client, &first_nonce, T0);
        // Un second défi remplace le premier : l'ancienne signature ne couvre
        // plus le nonce attendu.
        let _ = guard.issue_at(peer, T0).unwrap();
        assert_eq!(
            guard.verify_at(&peer, &old_signature, T0, T0),
            AuthOutcome::Reject
        );
    }

    #[test]
    fn end_session_clears_state() {
        let (mut guard, client, peer) = setup(&["r"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        let _ = guard.verify_at(&peer, &sign(&client, &nonce, T0), T0, T0);
        assert!(guard.session_roles(&peer).is_some());
        guard.end_session(&peer);
        assert_eq!(guard.session_roles(&peer), None);
    }

    #[test]
    fn authenticated_peers_reflects_active_sessions_only() {
        let (mut guard, client_a, peer_a) = setup(&["r"]);
        let client_b = identity::generate();
        let peer_b = client_b.public().to_peer_id();
        guard.whitelist_mut().allow(peer_b, ["r"]);

        assert!(
            guard.authenticated_peers().next().is_none(),
            "aucune session avant authentification"
        );

        let nonce_a = nonce_of(&guard.issue_at(peer_a, T0).unwrap());
        let _ = guard.verify_at(&peer_a, &sign(&client_a, &nonce_a, T0), T0, T0);
        assert_eq!(
            guard.authenticated_peers().collect::<Vec<_>>(),
            vec![peer_a]
        );

        let nonce_b = nonce_of(&guard.issue_at(peer_b, T0).unwrap());
        let _ = guard.verify_at(&peer_b, &sign(&client_b, &nonce_b, T0), T0, T0);
        let mut sessions: Vec<_> = guard.authenticated_peers().collect();
        sessions.sort();
        let mut expected = vec![peer_a, peer_b];
        expected.sort();
        assert_eq!(sessions, expected);

        guard.end_session(&peer_a);
        assert_eq!(
            guard.authenticated_peers().collect::<Vec<_>>(),
            vec![peer_b]
        );
    }

    #[test]
    fn hot_revocation_invalidates_live_session() {
        // Le pair s'authentifie, sa session est active…
        let (mut guard, client, peer) = setup(&["db-writer"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        let _ = guard.verify_at(&peer, &sign(&client, &nonce, T0), T0, T0);
        assert!(guard.session_roles(&peer).is_some());

        // …puis il est radié SANS déconnexion : sa session ne doit plus
        // ouvrir aucun nouveau flux (contournement d'autorisation, #1).
        assert!(guard.revoke(&peer), "le pair avait une session active");
        assert_eq!(
            guard.session_roles(&peer),
            None,
            "un pair radié ne doit plus être autorisé, même connexion ouverte"
        );
    }

    #[test]
    fn session_roles_follow_live_whitelist_changes() {
        // Un abaissement de rôle à chaud (via whitelist_mut) est autoritaire :
        // session_roles reflète la liste blanche courante, pas l'instantané
        // pris à l'authentification.
        let (mut guard, client, peer) = setup(&["db-writer", "admin"]);
        let nonce = nonce_of(&guard.issue_at(peer, T0).unwrap());
        let _ = guard.verify_at(&peer, &sign(&client, &nonce, T0), T0, T0);
        guard.whitelist_mut().allow(peer, ["db-writer"]);
        assert_eq!(
            guard.session_roles(&peer),
            Some(vec!["db-writer".to_string()]),
            "le rôle admin retiré ne doit plus figurer dans la session"
        );
    }

    #[test]
    fn client_answer_round_trip_through_real_clock() {
        let (mut guard, client, peer) = setup(&["r"]);
        let NuxResponse::Challenge { nonce, .. } = guard.issue(peer).unwrap() else {
            panic!("défi attendu");
        };
        let NuxRequest::ChallengeAnswer {
            signature,
            timestamp,
        } = answer_challenge(&client, &nonce).unwrap()
        else {
            panic!("réponse au défi attendue");
        };
        assert!(matches!(
            guard.verify(&peer, &signature, timestamp),
            AuthOutcome::Granted { .. }
        ));
    }
}
