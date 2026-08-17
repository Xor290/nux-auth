//! Compteurs internes d'un nœud `nux-relay` (réservations, circuits), au
//! format d'exposition Prometheus.
//!
//! Même principe que `nux_core::metrics` (crate `nux-core`) : ce démon
//! ne bind aucun port HTTP pour les servir — l'appelant écrit périodiquement
//! l'instantané ([`Metrics::to_prometheus_text`]) dans un fichier lu par un
//! sidecar externe (typiquement le textfile collector de `node_exporter`).
//!
//! Aucun champ nominatif (`PeerId`, adresse) n'y figure : uniquement des
//! compteurs agrégés.

use std::sync::atomic::{AtomicU64, Ordering};

/// Compteurs cumulés d'un `nux-relay`. Toujours actifs (coût négligeable :
/// quelques `fetch_add` par évènement) ; lus périodiquement par l'appelant
/// pour produire un instantané.
#[derive(Debug, Default)]
pub struct Metrics {
    reservations_total: AtomicU64,
    reservations_denied_total: AtomicU64,
    reservations_expired_total: AtomicU64,
    circuits_opened_total: AtomicU64,
    circuits_active: AtomicU64,
}

impl Metrics {
    /// Une réservation de circuit a été acceptée (`relay::Event::ReservationReqAccepted`).
    pub fn record_reservation_accepted(&self) {
        self.reservations_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Une réservation de circuit a été refusée (`relay::Event::ReservationReqDenied`).
    pub fn record_reservation_denied(&self) {
        self.reservations_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Une réservation de circuit a expiré (`relay::Event::ReservationTimedOut`).
    pub fn record_reservation_expired(&self) {
        self.reservations_expired_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Un circuit relayé a été établi (`relay::Event::CircuitReqAccepted`).
    pub fn record_circuit_opened(&self) {
        self.circuits_opened_total.fetch_add(1, Ordering::Relaxed);
        self.circuits_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Un circuit relayé s'est refermé (`relay::Event::CircuitClosed`).
    pub fn record_circuit_closed(&self) {
        self.circuits_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Instantané au format d'exposition Prometheus (texte brut).
    pub fn to_prometheus_text(&self) -> String {
        format!(
            "\
# HELP nux_relay_reservations_total Réservations de circuit acceptées.
# TYPE nux_relay_reservations_total counter
nux_relay_reservations_total {}
# HELP nux_relay_reservations_denied_total Réservations de circuit refusées.
# TYPE nux_relay_reservations_denied_total counter
nux_relay_reservations_denied_total {}
# HELP nux_relay_reservations_expired_total Réservations de circuit expirées.
# TYPE nux_relay_reservations_expired_total counter
nux_relay_reservations_expired_total {}
# HELP nux_relay_circuits_opened_total Circuits relayés établis avec succès.
# TYPE nux_relay_circuits_opened_total counter
nux_relay_circuits_opened_total {}
# HELP nux_relay_circuits_active Circuits relayés actuellement ouverts.
# TYPE nux_relay_circuits_active gauge
nux_relay_circuits_active {}
",
            self.reservations_total.load(Ordering::Relaxed),
            self.reservations_denied_total.load(Ordering::Relaxed),
            self.reservations_expired_total.load(Ordering::Relaxed),
            self.circuits_opened_total.load(Ordering::Relaxed),
            self.circuits_active.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_reflect_recorded_events() {
        let m = Metrics::default();
        m.record_reservation_accepted();
        m.record_reservation_accepted();
        m.record_reservation_denied();
        m.record_reservation_expired();
        m.record_circuit_opened();
        m.record_circuit_opened();
        m.record_circuit_closed();

        let text = m.to_prometheus_text();
        assert!(text.contains("nux_relay_reservations_total 2"));
        assert!(text.contains("nux_relay_reservations_denied_total 1"));
        assert!(text.contains("nux_relay_reservations_expired_total 1"));
        assert!(text.contains("nux_relay_circuits_opened_total 2"));
        assert!(text.contains("nux_relay_circuits_active 1"));
    }

    #[test]
    fn never_contains_a_peer_id() {
        let m = Metrics::default();
        m.record_reservation_accepted();
        let text = m.to_prometheus_text();
        assert!(
            !text.contains("12D3Koo"),
            "un PeerId ne doit jamais apparaître ici: {text}"
        );
    }
}
