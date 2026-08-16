//! Compteurs internes d'un nœud Nux (authentification, tunnels, octets
//! relayés), au format d'exposition Prometheus.
//!
//! `nux-core` ne bind **jamais** de port réseau pour les servir : la
//! bibliothèque se contente de les compter et de savoir les rendre en texte
//! ([`Metrics::to_prometheus_text`]) — à charge de l'appelant (le CLI)
//! d'écrire cet instantané où bon lui semble (typiquement un fichier lu par
//! un sidecar externe, ex. le textfile collector de `node_exporter`).
//! Ajouter un endpoint HTTP directement sur ce démon romprait le silence
//! radio qu'il applique partout ailleurs face à un pair non authentifié.
//!
//! Aucun champ nominatif (`PeerId`, adresse) n'y figure : uniquement des
//! compteurs agrégés, par prudence même si ce fichier finissait mal protégé.

use std::sync::atomic::{AtomicU64, Ordering};

/// Compteurs cumulés d'un nœud, `Guard` comme `Client`. Toujours actifs (coût
/// négligeable : quelques `fetch_add` par évènement) ; lus périodiquement par
/// l'appelant pour produire un instantané.
#[derive(Debug, Default)]
pub struct Metrics {
    auth_granted: AtomicU64,
    auth_denied: AtomicU64,
    tunnels_opened: AtomicU64,
    tunnels_denied: AtomicU64,
    tunnels_active: AtomicU64,
    bytes_from_peer: AtomicU64,
    bytes_to_peer: AtomicU64,
}

impl Metrics {
    pub(crate) fn record_auth_granted(&self) {
        self.auth_granted.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_auth_denied(&self) {
        self.auth_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_tunnel_denied(&self) {
        self.tunnels_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_tunnel_started(&self) {
        self.tunnels_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_tunnel_finished(&self, outcome: crate::tunnel::TunnelOutcome) {
        self.tunnels_active.fetch_sub(1, Ordering::Relaxed);
        if let crate::tunnel::TunnelOutcome::Served {
            bytes_from_peer,
            bytes_to_peer,
        } = outcome
        {
            self.tunnels_opened.fetch_add(1, Ordering::Relaxed);
            self.bytes_from_peer
                .fetch_add(bytes_from_peer, Ordering::Relaxed);
            self.bytes_to_peer
                .fetch_add(bytes_to_peer, Ordering::Relaxed);
        } else {
            self.tunnels_denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Instantané au format d'exposition Prometheus (texte brut).
    pub fn to_prometheus_text(&self) -> String {
        format!(
            "\
# HELP nux_auth_granted_total Authentifications réussies.
# TYPE nux_auth_granted_total counter
nux_auth_granted_total {}
# HELP nux_auth_denied_total Authentifications refusées (pair inconnu, signature invalide, arrêt en cours).
# TYPE nux_auth_denied_total counter
nux_auth_denied_total {}
# HELP nux_tunnels_opened_total Tunnels établis avec succès (acquittement envoyé).
# TYPE nux_tunnels_opened_total counter
nux_tunnels_opened_total {}
# HELP nux_tunnels_denied_total Flux tunnel abandonnés avant établissement (silence radio).
# TYPE nux_tunnels_denied_total counter
nux_tunnels_denied_total {}
# HELP nux_tunnels_active Tunnels actuellement en cours de relais.
# TYPE nux_tunnels_active gauge
nux_tunnels_active {}
# HELP nux_bytes_from_peer_total Octets reçus du pair et relayés vers le service local.
# TYPE nux_bytes_from_peer_total counter
nux_bytes_from_peer_total {}
# HELP nux_bytes_to_peer_total Octets reçus du service local et relayés vers le pair.
# TYPE nux_bytes_to_peer_total counter
nux_bytes_to_peer_total {}
",
            self.auth_granted.load(Ordering::Relaxed),
            self.auth_denied.load(Ordering::Relaxed),
            self.tunnels_opened.load(Ordering::Relaxed),
            self.tunnels_denied.load(Ordering::Relaxed),
            self.tunnels_active.load(Ordering::Relaxed),
            self.bytes_from_peer.load(Ordering::Relaxed),
            self.bytes_to_peer.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::TunnelOutcome;

    #[test]
    fn counters_reflect_recorded_events() {
        let m = Metrics::default();
        m.record_auth_granted();
        m.record_auth_granted();
        m.record_auth_denied();
        m.record_tunnel_started();
        m.record_tunnel_finished(TunnelOutcome::Served {
            bytes_from_peer: 10,
            bytes_to_peer: 20,
        });
        m.record_tunnel_started();
        m.record_tunnel_finished(TunnelOutcome::Denied);
        m.record_tunnel_denied();

        let text = m.to_prometheus_text();
        assert!(text.contains("nux_auth_granted_total 2"));
        assert!(text.contains("nux_auth_denied_total 1"));
        assert!(text.contains("nux_tunnels_opened_total 1"));
        // Un abandon compté par `record_tunnel_finished(Denied)` et un autre
        // par `record_tunnel_denied()` directement (cas refusé avant même
        // `record_tunnel_started`) : deux motifs distincts, même compteur.
        assert!(text.contains("nux_tunnels_denied_total 2"));
        assert!(text.contains("nux_tunnels_active 0"));
        assert!(text.contains("nux_bytes_from_peer_total 10"));
        assert!(text.contains("nux_bytes_to_peer_total 20"));
    }

    #[test]
    fn never_contains_a_peer_id_or_address() {
        // Rappel du cadrage : uniquement des compteurs agrégés. Un futur
        // ajout qui interpolerait un PeerId/adresse dans ce texte serait une
        // régression — ce test échouerait s'il introduisait, par exemple,
        // un identifiant base58 (les compteurs restent des entiers courts).
        let m = Metrics::default();
        m.record_auth_granted();
        let text = m.to_prometheus_text();
        assert!(
            !text.contains("12D3Koo"),
            "un PeerId ne doit jamais apparaître ici: {text}"
        );
    }
}
