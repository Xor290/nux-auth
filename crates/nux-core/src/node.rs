//! Nœud Nux : enveloppe typée autour du `Swarm` libp2p.

use crate::auth::{self, AuthOutcome, GuardAuthenticator, MAX_CLOCK_SKEW_SECS, Whitelist};
use crate::error::NuxError;
use crate::metrics::Metrics;
use crate::protocol::{NuxCodec, NuxRequest, NuxResponse, TUNNEL_PROTOCOL};
use crate::tunnel::{self, TunnelRegistry, TunnelStream};
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, dcutr, relay, rendezvous};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
/// Rôle d'une instance Nux dans la topologie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    /// Côté application : intercepte un port local et initie le tunnel.
    Client,
    /// Côté ressource : détient la liste blanche et injecte le flux vers le
    /// service local (BDD…). N'émet rien vers les pairs non authentifiés.
    Guard,
}

/// Commande de mutation à chaud de la liste blanche d'un Guard, injectée via
/// le canal de [`NuxNode::run_guard_with_control`]. Alimentée aujourd'hui
/// par le rechargement `SIGHUP` du CLI ; destinée à porter aussi, demain, une
/// synchronisation externe (diffusion Gossipsub de l'édition entreprise).
#[derive(Debug, Clone)]
pub enum GuardControl {
    /// Radie un pair : retrait de la liste blanche, session close, et coupure
    /// de sa connexion (donc de ses tunnels en cours).
    Revoke(PeerId),
    /// Autorise (ou met à jour les rôles d')un pair.
    Allow {
        /// Pair concerné.
        peer: PeerId,
        /// Rôles à lui accorder.
        roles: Vec<String>,
    },
    /// Remplace intégralement la liste blanche courante (rechargement de
    /// configuration, ex. `SIGHUP` côté CLI). Tout pair qui possédait une
    /// session active et n'apparaît plus dans la nouvelle liste est radié et
    /// **déconnecté immédiatement** (ses tunnels en cours sont coupés, pas
    /// seulement bloqués pour l'avenir). Un pair dont seuls les rôles
    /// changent garde sa connexion : les rôles courants sont reconsultés à
    /// chaque ouverture de tunnel ([`GuardAuthenticator::session_roles`]),
    /// aucune action supplémentaire n'est nécessaire ici.
    ReloadWhitelist(Whitelist),
    /// Demande l'arrêt gracieux du Guard : les nouvelles authentifications
    /// et ouvertures de tunnel sont désormais silencieusement refusées (même
    /// traitement que tout autre refus — aucun octet distinctif au pair),
    /// mais les tunnels déjà en cours ont jusqu'à `grace_period` pour se
    /// terminer d'eux-mêmes. [`NuxNode::run_guard_with_control`] retourne
    /// dès que le dernier tunnel se termine, ou de force à l'expiration du
    /// délai — au CLI de quitter le processus une fois cet appel revenu.
    Shutdown {
        /// Délai maximal laissé aux tunnels en cours pour se terminer.
        grace_period: std::time::Duration,
    },
}

pub use behaviour::{NuxBehaviour, NuxBehaviourEvent};

// Sous-module dédié au derive `NetworkBehaviour` : l'énum d'événements qu'il
// génère ne peut pas porter de documentation par variante, d'où l'exemption
// de `missing_docs` limitée à ce périmètre.
mod behaviour {
    #![allow(missing_docs)]

    use super::*;

    /// Comportement réseau composite du nœud.
    ///
    /// Phases 1-2 : protocole d'authentification. Phase 3 : flux bruts
    /// multiplexés du tunneling. Phase 4 : rate limiting des connexions
    /// entrantes par IP. L'édition entreprise y ajoutera la synchronisation
    /// de liste blanche par Gossipsub.
    #[derive(NetworkBehaviour)]
    pub struct NuxBehaviour {
        /// Cadence de connexions entrantes par IP — premier champ pour être
        /// consulté avant tout autre comportement au stade *pending*, avant
        /// le handshake Noise.
        pub rate_limit: crate::rate_limit::Behaviour,
        /// Handshake challenge-response `/nux/auth/1.0.0`.
        pub auth: request_response::Behaviour<NuxCodec>,
        /// Flux bruts `/nux/tunnel/1.0.0` portés par Yamux (Phase 3).
        pub tunnel: libp2p_stream::Behaviour,
        /// Côté client d'un circuit relay v2 : réservation auprès d'un
        /// `nux-relay` et composition via une adresse `/p2p-circuit`
        /// quand le pair visé est derrière NAT.
        pub relay_client: relay::client::Behaviour,
        /// Hole-punching (DCUtR) : bascule une connexion relayée vers une
        /// connexion directe dès que les deux extrémités y parviennent.
        pub dcutr: dcutr::Behaviour,
        /// Découverte de pairs par nom logique (namespace) auprès d'un point
        /// de rendezvous (porté par `nux-relay`) : un Guard s'y enregistre,
        /// un Client y résout un namespace en pairs joignables. Ne prouve
        /// aucune identité — seule l'authentification `/nux/auth/1.0.0`
        /// qui suit fait foi.
        pub rendezvous: rendezvous::client::Behaviour,
        pub keep_alive: libp2p::ping::Behaviour,
    }
}

/// Événement du protocole d'authentification, réexporté pour l'appelant.
pub type AuthEvent = request_response::Event<NuxRequest, NuxResponse>;

/// Nœud Nux construit par [`crate::NuxNodeBuilder`].
pub struct NuxNode {
    swarm: Swarm<NuxBehaviour>,
    mode: NodeMode,
    // Nécessaire côté Client pour signer les défis. La clé secrète interne
    // (ed25519-dalek) est effacée de la mémoire à la destruction (zeroize).
    keypair: Keypair,
    // Poignée clonable d'ouverture de flux tunnel (côté Client).
    tunnel_control: tunnel::Control,
    // Flux tunnel entrants ; consommés par `run_guard_with_tunnels`.
    tunnel_streams: libp2p_stream::IncomingStreams,
    // Non-`None` dès qu'un arrêt gracieux a été demandé (`GuardControl::
    // Shutdown`) : `handle_auth_request` s'en sert pour refuser en silence
    // toute nouvelle authentification/tunnel, `run_guard_loop` pour couper
    // de force les tunnels restants une fois ce délai dépassé.
    shutdown_deadline: Option<std::time::Instant>,
    metrics: Arc<Metrics>,
}

impl NuxNode {
    pub(crate) fn new(swarm: Swarm<NuxBehaviour>, mode: NodeMode, keypair: Keypair) -> Self {
        let mut tunnel_control = swarm.behaviour().tunnel.new_control();
        let tunnel_streams = tunnel_control
            .accept(TUNNEL_PROTOCOL)
            // Unique enregistrement du protocole, effectué à la construction :
            // `AlreadyRegistered` est impossible ici.
            .expect("le protocole tunnel n'est enregistré qu'une seule fois, à la construction");
        Self {
            swarm,
            mode,
            keypair,
            tunnel_control,
            tunnel_streams,
            shutdown_deadline: None,
            metrics: Arc::new(Metrics::default()),
        }
    }

    /// Identité publique du nœud — c'est elle qui figure dans les listes
    /// blanches des Guards.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Compteurs internes (authentifications, tunnels, octets relayés) de ce
    /// nœud, pour un export périodique par l'appelant (voir
    /// [`crate::metrics`]) — `nux-core` ne les sert jamais lui-même sur le
    /// réseau.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Rôle du nœud.
    pub fn mode(&self) -> NodeMode {
        self.mode
    }

    /// Compose un pair distant par son adresse.
    pub fn dial(&mut self, addr: Multiaddr) -> crate::Result<()> {
        self.swarm
            .dial(addr)
            .map_err(|e| NuxError::Dial(e.to_string()))
    }

    /// Ajoute une adresse d'écoute après construction — notamment une
    /// adresse `/p2p-circuit` pour réserver un circuit relay une fois
    /// connecté au relay ([`Self::dial`] au préalable). Un échec ici (relay
    /// injoignable, protocole non supporté) n'est jamais fatal au nœud :
    /// à l'appelant de le journaliser sans interrompre le service sur ses
    /// autres adresses.
    pub fn listen_on(&mut self, addr: Multiaddr) -> crate::Result<()> {
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    /// Recompose un pair dont le `PeerId` est déjà connu (reconnexion). À la
    /// différence de [`Self::dial`] (adresse nue, pair inconnu tant que Noise
    /// n'a pas abouti), cibler le `PeerId` fait porter tout échec de
    /// connexion par `SwarmEvent::OutgoingConnectionError` avec `peer_id:
    /// Some(peer)` plutôt que `None` — condition nécessaire pour que
    /// [`Self::authenticate`] détecte l'échec au lieu d'attendre
    /// indéfiniment un `ConnectionEstablished` qui ne viendra jamais.
    fn redial_known_peer(&mut self, peer: PeerId, addr: Multiaddr) -> crate::Result<()> {
        self.swarm
            .dial(DialOpts::peer_id(peer).addresses(vec![addr]).build())
            .map_err(|e| NuxError::Dial(e.to_string()))
    }

    /// Émet une requête d'authentification vers un pair connecté.
    pub fn send_request(&mut self, peer: &PeerId, request: NuxRequest) -> OutboundRequestId {
        self.swarm.behaviour_mut().auth.send_request(peer, request)
    }

    /// Répond à une requête reçue. Un `Err` signifie que le canal est déjà
    /// fermé (pair déconnecté ou délai expiré).
    pub fn send_response(
        &mut self,
        channel: ResponseChannel<NuxResponse>,
        response: NuxResponse,
    ) -> std::result::Result<(), NuxResponse> {
        self.swarm
            .behaviour_mut()
            .auth
            .send_response(channel, response)
    }

    /// Prochain événement du swarm. C'est la boucle de pilotage : l'appelant
    /// (démon CLI, tests d'intégration) consomme ce flux en continu.
    pub async fn next_event(&mut self) -> SwarmEvent<NuxBehaviourEvent> {
        self.swarm.select_next_some().await
    }

    /// Attend la première adresse d'écoute effective (utile quand on écoute
    /// sur un port 0 attribué par l'OS). Les autres événements survenus
    /// entre-temps sont journalisés puis ignorés.
    pub async fn wait_for_listen_addr(&mut self) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = self.next_event().await {
                return address;
            }
        }
    }

    /// Attend l'établissement de la prochaine connexion et retourne le pair
    /// joint, ou l'erreur de composition sortante.
    ///
    /// À réserver aux dials à un seul saut (adresse sans `PeerId` cible
    /// connu d'avance) : au travers d'un circuit relay (`/p2p-circuit`), la
    /// première connexion établie est celle vers le **relay**, pas vers le
    /// pair effectivement visé — voir [`Self::wait_for_peer`] dans ce cas.
    pub async fn next_connection(&mut self) -> crate::Result<PeerId> {
        loop {
            match self.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => return Ok(peer_id),
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    return Err(NuxError::Dial(error.to_string()));
                }
                _ => {}
            }
        }
    }

    /// Attend l'établissement d'une connexion vers `peer` spécifiquement, en
    /// ignorant toute connexion établie entre-temps vers un autre pair. Cible
    /// le cas d'un dial au travers d'un circuit relay (`/p2p-circuit`) : la
    /// connexion vers le relay (saut intermédiaire) s'établit avant celle
    /// vers le pair réellement visé, et [`Self::next_connection`]
    /// retournerait alors le mauvais `PeerId`.
    pub async fn wait_for_peer(&mut self, peer: PeerId) -> crate::Result<()> {
        loop {
            match self.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer => {
                    return Ok(());
                }
                SwarmEvent::OutgoingConnectionError {
                    peer_id: Some(p),
                    error,
                    ..
                } if p == peer => {
                    return Err(NuxError::Dial(error.to_string()));
                }
                _ => {}
            }
        }
    }

    /// Attend la confirmation d'une réservation de circuit auprès de
    /// `relay_node` (déjà demandée via [`Self::listen_on`] sur une adresse
    /// `/p2p-circuit`). [`Self::listen_on`] ne fait que **mettre en file**
    /// la demande — l'appeler puis enchaîner immédiatement sur
    /// [`Self::register_namespace`] échoue avec « no externally reachable
    /// addresses », l'adresse `/p2p-circuit` n'étant confirmée comme externe
    /// qu'à la réception de cet événement.
    pub async fn wait_for_circuit_reservation(&mut self, relay_node: PeerId) -> crate::Result<()> {
        loop {
            match self.next_event().await {
                SwarmEvent::Behaviour(NuxBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted {
                        relay_peer_id: rz, ..
                    },
                )) if rz == relay_node => return Ok(()),
                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == relay_node => {
                    return Err(NuxError::Network(
                        "connexion au relay perdue avant confirmation de la réservation".into(),
                    ));
                }
                _ => {}
            }
        }
    }

    /// Côté Guard : s'enregistre sous `namespace` auprès du point de
    /// rendezvous `rendezvous_node` (déjà connecté — voir [`Self::dial`] +
    /// [`Self::wait_for_peer`]). Exige au moins une adresse externe déjà
    /// confirmée : voir [`Self::wait_for_circuit_reservation`], à appeler
    /// avant celle-ci si l'adresse externe provient d'un circuit relay —
    /// sans quoi `rendezvous::client::Behaviour` refuse localement, avant
    /// tout échange réseau.
    ///
    /// L'enregistrement est un `PeerRecord` **signé par cette identité** :
    /// le point de rendezvous ne peut pas forger une entrée au nom d'un
    /// autre pair, seulement relayer ce qu'un pair a lui-même signé.
    pub async fn register_namespace(
        &mut self,
        rendezvous_node: PeerId,
        namespace: rendezvous::Namespace,
    ) -> crate::Result<()> {
        self.swarm
            .behaviour_mut()
            .rendezvous
            .register(namespace.clone(), rendezvous_node, None)
            .map_err(|e| NuxError::Network(e.to_string()))?;
        loop {
            match self.next_event().await {
                SwarmEvent::Behaviour(NuxBehaviourEvent::Rendezvous(
                    rendezvous::client::Event::Registered {
                        rendezvous_node: rz,
                        namespace: ns,
                        ..
                    },
                )) if rz == rendezvous_node && ns == namespace => return Ok(()),
                SwarmEvent::Behaviour(NuxBehaviourEvent::Rendezvous(
                    rendezvous::client::Event::RegisterFailed {
                        rendezvous_node: rz,
                        namespace: ns,
                        error,
                    },
                )) if rz == rendezvous_node && ns == namespace => {
                    return Err(NuxError::Network(format!(
                        "enregistrement rendezvous refusé: {error:?}"
                    )));
                }
                _ => {}
            }
        }
    }

    /// Côté Client : résout `namespace` auprès de `rendezvous_node` (déjà
    /// connecté), puis compose chaque pair renvoyé jusqu'à ce que l'un
    /// d'eux accepte la connexion — plusieurs Guards peuvent partager un
    /// même namespace (répartition, redondance). Retourne le premier pair
    /// joint et l'adresse qui a fonctionné (utile à l'appelant pour la
    /// reconnexion ultérieure, ex. [`Self::run_client_session`], qui ne
    /// refait pas la découverte à chaque coupure). L'authentification
    /// `/nux/auth/1.0.0` reste à faire par l'appelant, la découverte ne
    /// prouvant aucune identité.
    pub async fn discover_and_dial(
        &mut self,
        rendezvous_node: PeerId,
        namespace: rendezvous::Namespace,
    ) -> crate::Result<(PeerId, Multiaddr)> {
        const PER_ADDRESS_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

        self.swarm.behaviour_mut().rendezvous.discover(
            Some(namespace.clone()),
            None,
            None,
            rendezvous_node,
        );
        let registrations = loop {
            match self.next_event().await {
                SwarmEvent::Behaviour(NuxBehaviourEvent::Rendezvous(
                    rendezvous::client::Event::Discovered {
                        rendezvous_node: rz,
                        registrations,
                        ..
                    },
                )) if rz == rendezvous_node => break registrations,
                SwarmEvent::Behaviour(NuxBehaviourEvent::Rendezvous(
                    rendezvous::client::Event::DiscoverFailed {
                        rendezvous_node: rz,
                        error,
                        ..
                    },
                )) if rz == rendezvous_node => {
                    return Err(NuxError::Network(format!(
                        "découverte rendezvous échouée: {error:?}"
                    )));
                }
                _ => {}
            }
        };
        if registrations.is_empty() {
            return Err(NuxError::Network(format!(
                "aucun pair enregistré sous le namespace `{namespace}`"
            )));
        }
        for registration in &registrations {
            let peer = registration.record.peer_id();
            for addr in registration.record.addresses() {
                if self.redial_known_peer(peer, addr.clone()).is_err() {
                    continue;
                }
                if tokio::time::timeout(PER_ADDRESS_DIAL_TIMEOUT, self.wait_for_peer(peer))
                    .await
                    .is_ok_and(|r| r.is_ok())
                {
                    return Ok((peer, addr.clone()));
                }
            }
        }
        Err(NuxError::Network(format!(
            "aucun pair joignable sous le namespace `{namespace}`"
        )))
    }

    /// Côté Client : déroule le handshake challenge-response complet auprès
    /// d'un Guard connecté et retourne les rôles accordés.
    ///
    /// Séquence : `HandshakeInit` → réception du défi → signature de
    /// `nonce ‖ timestamp` avec la clé privée du nœud → `ChallengeAnswer` →
    /// `AccessGranted`. Une coupure sèche de la part du Guard (silence radio)
    /// se traduit par [`NuxError::AccessDenied`], indistinguable d'un refus
    /// explicite.
    pub async fn authenticate(&mut self, guard: &PeerId) -> crate::Result<Vec<String>> {
        if !self.swarm.is_connected(guard) {
            loop {
                match self.next_event().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == *guard => {
                        break;
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. }
                        if peer_id == Some(*guard) =>
                    {
                        return Err(NuxError::Dial(error.to_string()));
                    }
                    _ => {}
                }
            }
        }

        let mut awaiting = self.send_request(guard, NuxRequest::HandshakeInit);
        let mut challenge_answered = false;
        loop {
            match self.next_event().await {
                SwarmEvent::Behaviour(NuxBehaviourEvent::Auth(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    },
                )) if peer == *guard && request_id == awaiting => {
                    match (challenge_answered, response) {
                        (false, NuxResponse::Challenge { nonce, timestamp }) => {
                            if timestamp.abs_diff(auth::unix_now()) > MAX_CLOCK_SKEW_SECS {
                                tracing::warn!(
                                    %guard,
                                    "horloges désynchronisées avec le Guard: \
                                     l'authentification échouera probablement"
                                );
                            }
                            let answer = auth::answer_challenge(&self.keypair, &nonce)?;
                            awaiting = self.send_request(guard, answer);
                            challenge_answered = true;
                        }
                        (true, NuxResponse::AccessGranted { roles }) => return Ok(roles),
                        (_, NuxResponse::Denied) => return Err(NuxError::AccessDenied),
                        (_, other) => {
                            return Err(NuxError::Protocol(format!(
                                "réponse inattendue du Guard: {other:?}"
                            )));
                        }
                    }
                }
                SwarmEvent::Behaviour(NuxBehaviourEvent::Auth(
                    request_response::Event::OutboundFailure {
                        peer, request_id, ..
                    },
                )) if peer == *guard && request_id == awaiting => {
                    // Le Guard a coupé sans un octet : silence radio observé.
                    return Err(NuxError::AccessDenied);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == *guard => {
                    return Err(NuxError::AccessDenied);
                }
                _ => {}
            }
        }
    }

    /// Côté Client : boucle de service résiliente (Phase 4). Pilote le swarm
    /// et, si la connexion au Guard tombe — délai d'inactivité, coupure
    /// réseau, redémarrage du Guard —, recompose `guard_addr` et rejoue le
    /// handshake d'authentification avec un repli exponentiel (1 s → 30 s).
    /// Les redirections de ports actives ([`tunnel::forward_listener`])
    /// retrouvent alors un Guard prêt à servir leurs prochains tunnels.
    /// Ne retourne jamais tant que le swarm est vivant.
    ///
    /// `shutdown` déclenché : la boucle de reconnexion s'arrête, mais le
    /// swarm continue d'être piloté jusqu'à `grace_period` — nécessaire pour
    /// que les tunnels déjà ouverts par les redirections locales (voir
    /// [`Self::run_tunnel_client`]) continuent de transporter des octets
    /// pendant leur propre drainage, qui tourne dans des tâches séparées.
    pub async fn run_client_session(
        &mut self,
        guard: PeerId,
        guard_addr: Multiaddr,
        shutdown: tokio_util::sync::CancellationToken,
        grace_period: std::time::Duration,
    ) {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                event = self.next_event() => {
                    match event {
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            num_established: 0,
                            ..
                        } if peer_id == guard => {
                            tracing::warn!(%guard, "connexion au Guard perdue: reconnexion");
                            self.reauthenticate(guard, &guard_addr).await;
                        }
                        SwarmEvent::Behaviour(ref inner) if Self::log_relay_event(inner) => {}
                        event => tracing::trace!(?event, "événement swarm"),
                    }
                }
            }
        }
        tracing::info!(
            "arrêt demandé: maintien du swarm actif le temps du drainage des redirections locales"
        );
        let _ = tokio::time::timeout(grace_period, async {
            loop {
                self.next_event().await;
            }
        })
        .await;
    }

    /// Recompose le Guard et rejoue le handshake jusqu'au succès, avec repli
    /// exponentiel entre les tentatives.
    async fn reauthenticate(&mut self, guard: PeerId, guard_addr: &Multiaddr) {
        const INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
        const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);
        let mut backoff = INITIAL_BACKOFF;
        loop {
            let outcome = match self.redial_known_peer(guard, guard_addr.clone()) {
                Ok(()) => self.authenticate(&guard).await,
                Err(e) => Err(e),
            };
            match outcome {
                Ok(roles) => {
                    tracing::info!(%guard, ?roles, "session ré-établie auprès du Guard");
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        %guard,
                        error = %e,
                        nouvel_essai = ?backoff,
                        "ré-authentification échouée"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    /// Poignée clonable d'ouverture de tunnels, à distribuer aux tâches qui
    /// relaient des connexions ([`tunnel::open`], [`tunnel::forward_listener`]).
    /// Le swarm doit rester piloté en parallèle pour que les ouvertures
    /// aboutissent.
    pub fn tunnel_control(&self) -> tunnel::Control {
        self.tunnel_control.clone()
    }

    /// Côté Client : ouvre un tunnel vers `service` auprès du Guard, en
    /// pilotant le swarm le temps de l'ouverture, et retourne le flux prêt à
    /// relayer (l'en-tête de service est envoyé et l'acquittement du Guard
    /// consommé).
    ///
    /// Un refus du Guard — quel qu'en soit le motif — se manifeste par une
    /// coupure sèche et produit [`NuxError::AccessDenied`].
    pub async fn open_tunnel(
        &mut self,
        guard: PeerId,
        service: &str,
    ) -> crate::Result<TunnelStream> {
        let mut control = self.tunnel_control();
        let open = tunnel::open(&mut control, guard, service);
        tokio::pin!(open);
        loop {
            tokio::select! {
                result = &mut open => return result,
                event = self.swarm.select_next_some() => {
                    tracing::trace!(?event, "événement swarm");
                }
            }
        }
    }

    /// Côté Client : redirige en continu un port local déjà lié vers un
    /// service exposé par le Guard, tout en pilotant le swarm. Chaque
    /// connexion TCP acceptée sur `listener` devient un tunnel dédié.
    ///
    /// Retourne dès que `shutdown` est déclenché, après avoir laissé jusqu'à
    /// `grace_period` aux relais en cours pour se terminer d'eux-mêmes (le
    /// swarm continue d'être piloté pendant ce drainage — nécessaire pour que
    /// les flux tunnel déjà ouverts continuent de transporter des octets).
    pub async fn run_tunnel_client(
        &mut self,
        guard: PeerId,
        service: &str,
        listener: tokio::net::TcpListener,
        shutdown: tokio_util::sync::CancellationToken,
        grace_period: std::time::Duration,
    ) {
        let control = self.tunnel_control();
        let forward = tunnel::forward_listener(
            control,
            guard,
            service.to_owned(),
            listener,
            shutdown,
            grace_period,
        );
        tokio::pin!(forward);
        loop {
            tokio::select! {
                () = &mut forward => return,
                event = self.swarm.select_next_some() => {
                    tracing::trace!(?event, "événement swarm");
                }
            }
        }
    }

    /// Côté Client : redirige en continu une **socket Unix** locale déjà liée
    /// vers un service exposé par le Guard, tout en pilotant le swarm. Chaque
    /// connexion acceptée n'est relayée que si l'UID du process pair — fourni
    /// par le noyau via `SO_PEERCRED`, non falsifiable — figure dans
    /// `allowed_uids` ; sinon elle est fermée en silence
    /// ([`tunnel::forward_unix_listener`]).
    ///
    /// Retourne dès que `shutdown` est déclenché, avec le même drainage que
    /// [`Self::run_tunnel_client`].
    #[cfg(unix)]
    pub async fn run_tunnel_client_unix(
        &mut self,
        guard: PeerId,
        service: &str,
        listener: tokio::net::UnixListener,
        allowed_uids: Vec<u32>,
        shutdown: tokio_util::sync::CancellationToken,
        grace_period: std::time::Duration,
    ) {
        let control = self.tunnel_control();
        let forward = tunnel::forward_unix_listener(
            control,
            guard,
            service.to_owned(),
            listener,
            allowed_uids,
            shutdown,
            grace_period,
        );
        tokio::pin!(forward);
        loop {
            tokio::select! {
                () = &mut forward => return,
                event = self.swarm.select_next_some() => {
                    tracing::trace!(?event, "événement swarm");
                }
            }
        }
    }

    /// Côté Guard : boucle de service. Émet les défis, vérifie les réponses,
    /// applique le silence radio, et clôt les sessions à la déconnexion.
    /// Ne retourne jamais tant que le swarm est vivant.
    ///
    /// Cette variante ignore le tunneling (les flux entrants restent lettre
    /// morte) ; pour exposer des services, voir
    /// [`NuxNode::run_guard_with_tunnels`].
    pub async fn run_guard(&mut self, authenticator: &mut GuardAuthenticator) {
        loop {
            let event = self.next_event().await;
            self.handle_guard_event(authenticator, event);
        }
    }

    /// Côté Guard : boucle de service complète — authentification (Phase 2)
    /// et tunneling (Phase 3). Ne retourne jamais tant que le swarm est
    /// vivant.
    ///
    /// Chaque flux `/nux/tunnel/1.0.0` entrant n'est servi que si son pair
    /// détient une session authentifiée **encore en liste blanche** : les
    /// rôles courants sont alors capturés et l'autorisation par service se
    /// joue dans une tâche dédiée ([`tunnel::TunnelRegistry`]). Un flux d'un
    /// pair sans session (ou radié) est abandonné et sa connexion coupée,
    /// sans un octet (silence radio).
    ///
    /// Les flux concurrents sont plafonnés par pair et globalement
    /// ([`tunnel::TunnelRegistry::max_concurrent_streams`]) : un pair autorisé
    /// ne peut pas ouvrir un nombre illimité de tunnels pour épuiser le
    /// service backend (anti-amplification). Le flux excédentaire est
    /// abandonné en silence, sans couper la connexion (les tunnels légitimes
    /// du même pair continuent).
    pub async fn run_guard_with_tunnels(
        &mut self,
        authenticator: &mut GuardAuthenticator,
        registry: TunnelRegistry,
    ) {
        self.run_guard_loop(authenticator, registry, None).await
    }

    /// Côté Guard : identique à [`NuxNode::run_guard_with_tunnels`], mais
    /// écoute en plus un canal de contrôle pour muter la liste blanche à
    /// chaud — c'est le point d'entrée d'une synchronisation externe (à venir :
    /// diffusion Gossipsub de l'édition entreprise).
    ///
    /// Une [`GuardControl::Revoke`] radie le pair **et coupe sa connexion**,
    /// ce qui interrompt jusqu'aux tunnels déjà en cours de relais (le
    /// contrôle logique seul ne bloque que les nouveaux flux). Ne retourne
    /// jamais tant que le swarm est vivant.
    pub async fn run_guard_with_control(
        &mut self,
        authenticator: &mut GuardAuthenticator,
        registry: TunnelRegistry,
        control: tokio::sync::mpsc::Receiver<GuardControl>,
    ) {
        self.run_guard_loop(authenticator, registry, Some(control))
            .await
    }

    async fn run_guard_loop(
        &mut self,
        authenticator: &mut GuardAuthenticator,
        registry: TunnelRegistry,
        mut control: Option<tokio::sync::mpsc::Receiver<GuardControl>>,
    ) {
        // Sémaphore global + un sémaphore par pair, bornant les flux tunnel
        // simultanés. La table par pair ne contient que des pairs authentifiés
        // (donc en liste blanche) : sa taille est bornée par la liste blanche.
        let max_streams_total = registry.max_streams_total();
        let global = Arc::new(Semaphore::new(max_streams_total));
        let per_peer_cap = registry.max_streams_per_peer();
        let mut per_peer: HashMap<PeerId, Arc<Semaphore>> = HashMap::new();
        let registry = Arc::new(registry);
        // Pendant un arrêt gracieux, le relâchement d'un jeton de tunnel (fin
        // d'un flux) ne réveille pas cette boucle par lui-même : on revérifie
        // périodiquement plutôt que d'attendre systématiquement tout le délai
        // de grâce même quand le dernier tunnel s'est déjà terminé.
        let mut drain_check = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            let shutdown_deadline = self.shutdown_deadline;
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } = &event {
                        // Le pair est parti : on oublie son sémaphore.
                        per_peer.remove(peer_id);
                    }
                    self.handle_guard_event(authenticator, event);
                }
                Some((peer, stream)) = self.tunnel_streams.next() => {
                    if self.shutdown_deadline.is_some() {
                        // Silence radio, comme tout autre refus : arrêt en
                        // cours, aucun nouveau tunnel n'est accepté.
                        drop(stream);
                        tracing::debug!(%peer, "arrêt en cours: nouveau flux tunnel refusé");
                        self.metrics.record_tunnel_denied();
                        continue;
                    }
                    let Some(roles) = authenticator.session_roles(&peer) else {
                        drop(stream);
                        let _ = self.swarm.disconnect_peer_id(peer);
                        tracing::debug!(
                            %peer,
                            "flux tunnel sans session authentifiée: connexion coupée"
                        );
                        self.metrics.record_tunnel_denied();
                        continue;
                    };
                    // Réservation anti-amplification : un jeton global ET un
                    // jeton propre au pair, tenus le temps du relais.
                    let peer_sem = per_peer
                        .entry(peer)
                        .or_insert_with(|| Arc::new(Semaphore::new(per_peer_cap)));
                    let Ok(peer_permit) = Arc::clone(peer_sem).try_acquire_owned() else {
                        drop(stream);
                        tracing::debug!(%peer, "plafond de tunnels par pair atteint: flux abandonné");
                        self.metrics.record_tunnel_denied();
                        continue;
                    };
                    let Ok(global_permit) = Arc::clone(&global).try_acquire_owned() else {
                        drop(stream);
                        tracing::warn!(%peer, "plafond global de tunnels atteint: flux abandonné");
                        self.metrics.record_tunnel_denied();
                        continue;
                    };
                    let registry = Arc::clone(&registry);
                    let metrics = Arc::clone(&self.metrics);
                    metrics.record_tunnel_started();
                    tokio::spawn(async move {
                        let outcome = tunnel::serve_stream(peer, stream, roles, registry).await;
                        metrics.record_tunnel_finished(outcome);
                        // Les jetons sont libérés à la fin du relais.
                        drop(peer_permit);
                        drop(global_permit);
                    });
                }
                // Canal de contrôle : ne se déclenche jamais quand `control`
                // est `None` (pas de synchronisation externe câblée).
                cmd = async {
                    match &mut control {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match cmd {
                        Some(GuardControl::Shutdown { grace_period }) => {
                            tracing::info!(
                                ?grace_period,
                                "arrêt gracieux demandé: nouvelles authentifications et nouveaux tunnels refusés"
                            );
                            self.shutdown_deadline =
                                Some(std::time::Instant::now() + grace_period);
                        }
                        Some(GuardControl::Revoke(peer)) => {
                            if authenticator.revoke(&peer) {
                                // Coupe aussi les tunnels déjà en relais.
                                let _ = self.swarm.disconnect_peer_id(peer);
                                per_peer.remove(&peer);
                                tracing::info!(%peer, "pair radié à chaud: connexion coupée");
                            }
                        }
                        Some(GuardControl::Allow { peer, roles }) => {
                            authenticator.whitelist_mut().allow(peer, roles);
                            tracing::info!(%peer, "pair autorisé à chaud");
                        }
                        Some(GuardControl::ReloadWhitelist(new_whitelist)) => {
                            // Calculé AVANT le remplacement : qui perd tout
                            // accès sous la nouvelle liste, parmi les pairs
                            // actuellement authentifiés.
                            let to_revoke: Vec<PeerId> = authenticator
                                .authenticated_peers()
                                .filter(|peer| new_whitelist.roles(peer).is_none())
                                .collect();
                            *authenticator.whitelist_mut() = new_whitelist;
                            for peer in to_revoke {
                                // `revoke` nettoie aussi sessions/défis en
                                // attente : même chemin qu'une radiation
                                // individuelle, pas de logique dupliquée.
                                if authenticator.revoke(&peer) {
                                    let _ = self.swarm.disconnect_peer_id(peer);
                                    per_peer.remove(&peer);
                                    tracing::info!(
                                        %peer,
                                        "pair radié par rechargement de configuration: connexion coupée"
                                    );
                                }
                            }
                            tracing::info!("liste blanche rechargée à chaud");
                        }
                        // Canal fermé : on cesse de l'interroger.
                        None => control = None,
                    }
                }
                _ = drain_check.tick(), if shutdown_deadline.is_some() => {
                    if global.available_permits() == max_streams_total {
                        tracing::info!("arrêt gracieux: tous les tunnels en cours se sont terminés");
                        return;
                    }
                    if std::time::Instant::now() >= shutdown_deadline.expect("garde if ci-dessus") {
                        tracing::warn!(
                            "délai de grâce d'arrêt écoulé: tunnels restants coupés de force"
                        );
                        return;
                    }
                }
            }
        }
    }

    /// Traite un unique événement swarm côté Guard. Exposé séparément de
    /// [`NuxNode::run_guard`] pour permettre aux intégrateurs d'entrelacer
    /// leur propre logique dans la boucle d'événements.
    pub fn handle_guard_event(
        &mut self,
        authenticator: &mut GuardAuthenticator,
        event: SwarmEvent<NuxBehaviourEvent>,
    ) {
        match event {
            SwarmEvent::Behaviour(NuxBehaviourEvent::Auth(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => self.handle_auth_request(authenticator, peer, request, channel),
            // Dernière connexion du pair fermée : sa session tombe avec elle.
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => authenticator.end_session(&peer_id),
            SwarmEvent::Behaviour(ref inner) if Self::log_relay_event(inner) => {}
            other => tracing::trace!(event = ?other, "événement swarm"),
        }
    }

    /// Journalise les événements de connectivité assistée (réservation de
    /// circuit relay, hole-punch DCUtR) : jamais fatals — un échec de
    /// hole-punch signifie seulement que le trafic continue de transiter par
    /// le relay, pas une rupture de la session authentifiée. Retourne `true`
    /// si l'événement a été reconnu et journalisé (l'appelant n'a alors rien
    /// d'autre à en faire).
    fn log_relay_event(event: &NuxBehaviourEvent) -> bool {
        match event {
            NuxBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                ..
            }) => {
                tracing::info!(%relay_peer_id, renewal, "réservation de circuit relay acceptée");
                true
            }
            NuxBehaviourEvent::RelayClient(
                relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. },
            ) => {
                tracing::info!(%relay_peer_id, "circuit relayé sortant établi");
                true
            }
            NuxBehaviourEvent::RelayClient(relay::client::Event::InboundCircuitEstablished {
                src_peer_id,
                ..
            }) => {
                tracing::info!(%src_peer_id, "circuit relayé entrant établi");
                true
            }
            NuxBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result: Ok(_),
            }) => {
                tracing::info!(peer = %remote_peer_id, "hole-punch DCUtR réussi: connexion directe établie");
                true
            }
            NuxBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result: Err(e),
            }) => {
                tracing::warn!(
                    peer = %remote_peer_id,
                    error = %e,
                    "hole-punch DCUtR échoué: le trafic continue de transiter par le relay"
                );
                true
            }
            NuxBehaviourEvent::KeepAlive(_) => true,
            _ => false,
        }
    }

    fn handle_auth_request(
        &mut self,
        authenticator: &mut GuardAuthenticator,
        peer: PeerId,
        request: NuxRequest,
        channel: ResponseChannel<NuxResponse>,
    ) {
        match request {
            NuxRequest::HandshakeInit if self.shutdown_deadline.is_some() => {
                // Arrêt en cours : traité comme un pair hors liste blanche,
                // même silence radio — aucune distinction observable entre
                // « inconnu » et « le Guard s'arrête ».
                tracing::debug!(%peer, "arrêt en cours: nouvelle authentification refusée");
                self.metrics.record_auth_denied();
                self.silence(peer, channel);
            }
            NuxRequest::HandshakeInit => match authenticator.issue(peer) {
                Some(challenge) => {
                    if self.send_response(channel, challenge).is_err() {
                        tracing::debug!(%peer, "canal fermé avant l'envoi du défi");
                    }
                }
                None => {
                    self.metrics.record_auth_denied();
                    self.silence(peer, channel);
                }
            },
            NuxRequest::ChallengeAnswer {
                signature,
                timestamp,
            } => match authenticator.verify(&peer, &signature, timestamp) {
                AuthOutcome::Granted { roles } => {
                    tracing::info!(%peer, ?roles, "pair authentifié");
                    self.metrics.record_auth_granted();
                    let granted = NuxResponse::AccessGranted { roles };
                    if self.send_response(channel, granted).is_err() {
                        tracing::debug!(%peer, "canal fermé avant l'octroi d'accès");
                    }
                }
                AuthOutcome::Reject => {
                    self.metrics.record_auth_denied();
                    self.silence(peer, channel);
                }
            },
        }
    }

    /// Silence radio (cadrage §3.3) : le canal de réponse est abandonné sans
    /// qu'un octet ne parte, puis la connexion TCP est coupée immédiatement.
    /// Le motif de l'échec reste dans les journaux locaux.
    fn silence(&mut self, peer: PeerId, channel: ResponseChannel<NuxResponse>) {
        drop(channel);
        let _ = self.swarm.disconnect_peer_id(peer);
        tracing::debug!(%peer, "connexion coupée sans réponse");
    }

    /// Coupe toutes les connexions vers un pair. À appeler après une
    /// radiation ([`GuardAuthenticator::revoke`] a renvoyé `true`) pour
    /// interrompre les tunnels déjà en cours de relais : le contrôle logique
    /// bloque les *nouveaux* flux, mais seul l'arrêt de la connexion coupe un
    /// `copy_bidirectional` déjà lancé. Retourne `true` si le pair était
    /// connecté.
    pub fn disconnect(&mut self, peer: &PeerId) -> bool {
        self.swarm.disconnect_peer_id(*peer).is_ok()
    }

    /// Accès de bas niveau au swarm pour les intégrations avancées.
    pub fn swarm_mut(&mut self) -> &mut Swarm<NuxBehaviour> {
        &mut self.swarm
    }
}
