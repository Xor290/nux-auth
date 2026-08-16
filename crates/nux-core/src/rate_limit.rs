//! Rate limiting des connexions entrantes par adresse IP (Phase 4).
//!
//! Le contrôle s'applique au stade *pending* de la connexion, avant le
//! handshake Noise : une IP au-dessus de sa cadence se voit refuser la
//! connexion sans qu'aucun travail cryptographique ne soit engagé et sans
//! qu'un octet applicatif ne parte — vu du pair, la connexion TCP se ferme,
//! c'est tout (cohérent avec le silence radio du cadrage §3.3).
//!
//! La comptabilité est une fenêtre glissante par IP : au plus
//! `max_per_window` connexions acceptées par fenêtre. Les tentatives
//! refusées ne sont pas comptées — une IP qui martèle n'obtient jamais plus
//! que sa cadence, et retrouve du crédit à mesure que la fenêtre glisse. La
//! table est balayée périodiquement pour que les IP inactives ne retiennent
//! pas de mémoire, et sa taille est **plafonnée** ([`MAX_TRACKED_IPS`]) pour
//! qu'un balayage d'adresses sources (typiquement IPv6, espace immense) ne
//! puisse pas l'enfler indéfiniment.
//!
//! **Limite de conception** : le seuil est par IP source, donc il suppose
//! qu'une IP ≈ un client. Plusieurs clients légitimes derrière un même NAT
//! partagent le budget ; pour les y soustraire, inscrire leur IP en
//! exemption ([`RateLimiter::exempt`]).

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, dummy,
};
use libp2p::{PeerId, core::Endpoint, core::transport::PortUse};
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::fmt;
use std::net::IpAddr;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Cadence par défaut : nombre de connexions entrantes acceptées par IP et
/// par fenêtre.
pub const DEFAULT_MAX_PER_WINDOW: u32 = 30;
/// Fenêtre glissante par défaut.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
/// Nombre maximal d'IP suivies simultanément. Au-delà (et si un balayage ne
/// libère rien), les IP inconnues sont refusées : la mémoire du limiteur est
/// bornée face à un balayage d'adresses sources.
pub const MAX_TRACKED_IPS: usize = 100_000;

/// Limiteur à fenêtre glissante par adresse IP.
pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    max_tracked_ips: usize,
    hits: HashMap<IpAddr, VecDeque<Instant>>,
    exempt: HashSet<IpAddr>,
    last_sweep: Instant,
}

impl RateLimiter {
    /// Nouveau limiteur : au plus `max_per_window` connexions acceptées par
    /// IP sur toute fenêtre glissante de `window`.
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            max_tracked_ips: MAX_TRACKED_IPS,
            hits: HashMap::new(),
            exempt: HashSet::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Exempte une IP de confiance de toute limite (jamais comptée, jamais
    /// refusée, ne consomme pas d'entrée dans la table). Utile pour les
    /// clients légitimes derrière un NAT partagé.
    pub fn exempt(&mut self, ip: IpAddr) -> &mut Self {
        self.exempt.insert(ip);
        self
    }

    /// Enregistre une tentative de `ip` et dit si elle est admise.
    pub fn allow(&mut self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    fn allow_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.exempt.contains(&ip) {
            return true;
        }
        if now.duration_since(self.last_sweep) >= self.window {
            self.sweep(now);
        }
        let window = self.window;
        // IP encore inconnue alors que la table est saturée : on tente un
        // balayage de dernière minute, puis on refuse si rien ne s'est
        // libéré — les IP déjà suivies continuent d'être servies.
        if !self.hits.contains_key(&ip) && self.hits.len() >= self.max_tracked_ips {
            self.sweep(now);
            if self.hits.len() >= self.max_tracked_ips {
                tracing::warn!(%ip, "table de rate limiting saturée: IP inconnue refusée");
                return false;
            }
        }
        let hits = self.hits.entry(ip).or_default();
        Self::prune(hits, now, window);
        if hits.len() >= self.max_per_window as usize {
            return false;
        }
        hits.push_back(now);
        true
    }

    fn prune(hits: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        while hits
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            hits.pop_front();
        }
    }

    /// Balayage global : les IP sans activité dans la fenêtre sont oubliées,
    /// bornant la mémoire face à un balayage d'adresses sources.
    fn sweep(&mut self, now: Instant) {
        let window = self.window;
        self.hits.retain(|_, hits| {
            Self::prune(hits, now, window);
            !hits.is_empty()
        });
        self.last_sweep = now;
    }
}

/// Motif de refus (journal local uniquement : le pair ne voit qu'une
/// fermeture TCP).
#[derive(Debug)]
pub struct RateExceeded {
    ip: IpAddr,
}

impl fmt::Display for RateExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cadence de connexions dépassée pour {}", self.ip)
    }
}

impl std::error::Error for RateExceeded {}

/// Comportement libp2p appliquant un [`RateLimiter`] aux connexions
/// entrantes. Placé en tête du comportement composite pour être consulté
/// avant tout autre.
pub struct Behaviour {
    limiter: RateLimiter,
}

impl Behaviour {
    /// Nouveau comportement avec la cadence donnée.
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            limiter: RateLimiter::new(max_per_window, window),
        }
    }

    /// Nouveau comportement avec la cadence donnée et une liste d'IP de
    /// confiance exemptées de toute limite.
    pub fn with_exemptions(
        max_per_window: u32,
        window: Duration,
        exempt: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        let mut limiter = RateLimiter::new(max_per_window, window);
        for ip in exempt {
            limiter.exempt(ip);
        }
        Self { limiter }
    }
}

/// Extrait l'adresse IP source d'une multiaddr, si elle en porte une.
fn ip_of(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|proto| match proto {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        _: ConnectionId,
        _local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // Transport sans IP (tests en mémoire…) : rien à limiter.
        let Some(ip) = ip_of(remote) else {
            return Ok(());
        };
        if self.limiter.allow(ip) {
            Ok(())
        } else {
            tracing::debug!(%ip, "connexion entrante refusée: cadence dépassée");
            Err(ConnectionDenied::new(RateExceeded { ip }))
        }
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        // Le handler factice n'émet jamais rien (type vide).
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP_A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));
    const IP_B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 8));
    const WINDOW: Duration = Duration::from_secs(60);

    #[test]
    fn allows_up_to_max_then_blocks() {
        let mut limiter = RateLimiter::new(3, WINDOW);
        let t0 = Instant::now();
        assert!(limiter.allow_at(IP_A, t0));
        assert!(limiter.allow_at(IP_A, t0));
        assert!(limiter.allow_at(IP_A, t0));
        assert!(!limiter.allow_at(IP_A, t0));
        // Les refus ne consomment pas de crédit : toujours bloqué, sans plus.
        assert!(!limiter.allow_at(IP_A, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn window_slides_and_credit_returns() {
        let mut limiter = RateLimiter::new(2, WINDOW);
        let t0 = Instant::now();
        assert!(limiter.allow_at(IP_A, t0));
        assert!(limiter.allow_at(IP_A, t0 + Duration::from_secs(30)));
        assert!(!limiter.allow_at(IP_A, t0 + Duration::from_secs(50)));
        // À t0+61, la première tentative sort de la fenêtre : crédit rendu.
        assert!(limiter.allow_at(IP_A, t0 + Duration::from_secs(61)));
        // Mais pas deux : celle de t0+30 est encore dans la fenêtre.
        assert!(!limiter.allow_at(IP_A, t0 + Duration::from_secs(61)));
    }

    #[test]
    fn ips_are_independent() {
        let mut limiter = RateLimiter::new(1, WINDOW);
        let t0 = Instant::now();
        assert!(limiter.allow_at(IP_A, t0));
        assert!(!limiter.allow_at(IP_A, t0));
        assert!(limiter.allow_at(IP_B, t0));
    }

    #[test]
    fn zero_max_blocks_everything() {
        let mut limiter = RateLimiter::new(0, WINDOW);
        assert!(!limiter.allow_at(IP_A, Instant::now()));
    }

    #[test]
    fn sweep_forgets_idle_ips() {
        let mut limiter = RateLimiter::new(5, WINDOW);
        let t0 = Instant::now();
        assert!(limiter.allow_at(IP_A, t0));
        assert!(limiter.allow_at(IP_B, t0));
        assert_eq!(limiter.hits.len(), 2);
        // Un passage bien après la fenêtre déclenche le balayage : seules
        // les IP actives restent en mémoire.
        assert!(limiter.allow_at(IP_B, t0 + WINDOW + Duration::from_secs(1)));
        assert_eq!(limiter.hits.len(), 1);
        assert!(!limiter.hits.contains_key(&IP_A));
    }

    #[test]
    fn exempt_ip_is_never_limited() {
        let mut limiter = RateLimiter::new(1, WINDOW);
        limiter.exempt(IP_A);
        let t0 = Instant::now();
        // Bien au-delà de la cadence de 1 : l'IP exemptée passe toujours…
        for _ in 0..100 {
            assert!(limiter.allow_at(IP_A, t0));
        }
        // …et ne consomme aucune entrée dans la table.
        assert!(limiter.hits.is_empty());
        // Une IP non exemptée reste soumise à la limite.
        assert!(limiter.allow_at(IP_B, t0));
        assert!(!limiter.allow_at(IP_B, t0));
    }

    #[test]
    fn tracked_ip_table_is_capped() {
        let mut limiter = RateLimiter::new(5, WINDOW);
        limiter.max_tracked_ips = 2;
        let t0 = Instant::now();
        // Deux IP occupent la table…
        assert!(limiter.allow_at(IP_A, t0));
        assert!(limiter.allow_at(IP_B, t0));
        // …une troisième IP inconnue est refusée (table saturée), sans que la
        // mémoire n'enfle : la table reste à sa borne.
        let ip_c = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));
        assert!(!limiter.allow_at(ip_c, t0));
        assert_eq!(limiter.hits.len(), 2);
        // Mais les IP déjà suivies continuent d'être servies.
        assert!(limiter.allow_at(IP_A, t0));
    }

    #[test]
    fn ip_extraction_from_multiaddr() {
        let tcp: Multiaddr = "/ip4/203.0.113.7/tcp/4588".parse().unwrap();
        assert_eq!(ip_of(&tcp), Some(IP_A));
        let ip6: Multiaddr = "/ip6/::1/tcp/4588".parse().unwrap();
        assert_eq!(ip_of(&ip6), Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
        let memory: Multiaddr = "/memory/42".parse().unwrap();
        assert_eq!(ip_of(&memory), None);
    }
}
