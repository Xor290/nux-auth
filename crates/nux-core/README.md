# nux-core

Moteur d'**Nux-Auth** : tunnels applicatifs chiffrés et authentifiés entre
serveurs, bâtis sur la couche pair-à-pair de [`rust-libp2p`](https://libp2p.io/)
— sans VPN, sans serveur SSO central. C'est la bibliothèque ; le binaire
`nux` (démon CLI) vit dans [`crates/nux-cli`](../nux-cli), documenté avec le
reste du produit dans le [README racine](../../README.md).

Trois piliers, détaillés (menaces, diagrammes de séquence) dans le README
racine :

- **SSO décentralisé** : l'identité d'un serveur est sa clé publique
  (`PeerId`) ; l'accès se prouve par challenge-response Ed25519, validé
  localement par le Guard contre sa liste blanche (consultation en temps
  constant).
- **Tunneling furtif** : capture d'un flux TCP local, encapsulation chiffrée
  de bout en bout (Noise) sur un flux Yamux dédié, réinjection sur
  `127.0.0.1` distant.
- **Masquage de port** : silence radio total face à un pair non
  authentifié — aucune erreur verbeuse ne quitte jamais le nœud, la
  connexion se coupe, c'est tout.

## Usage minimal

```rust,no_run
use nux_core::{GuardAuthenticator, NodeMode, NuxNodeBuilder, TunnelRegistry, Whitelist};

async fn run_guard(client_peer: nux_core::PeerId) -> nux_core::Result<()> {
    // Côté Guard : écoute, liste blanche, service exposé.
    let mut node = NuxNodeBuilder::new()
        .mode(NodeMode::Guard)
        .identity_file("/etc/nux/node.key")
        .listen_on("/ip4/0.0.0.0/tcp/4588".parse().expect("multiaddr valide"))
        .build()?;

    let mut whitelist = Whitelist::new();
    whitelist.allow(client_peer, vec!["db-writer".to_string()]);
    let mut authenticator = GuardAuthenticator::new(whitelist);

    let mut registry = TunnelRegistry::new();
    registry.expose(
        "postgres",
        "127.0.0.1:5432".parse().expect("adresse valide"),
        Some("db-writer".into()),
    );

    node.run_guard_with_tunnels(&mut authenticator, registry).await;
    Ok(())
}
```

```rust,no_run
use nux_core::{NodeMode, NuxNodeBuilder, PeerId};

async fn run_client(guard: PeerId) -> nux_core::Result<()> {
    // Côté Client : authentification puis ouverture d'un tunnel.
    let mut node = NuxNodeBuilder::new().mode(NodeMode::Client).build()?;
    node.dial("/ip4/203.0.113.10/tcp/4588".parse().expect("multiaddr valide"))?;
    let _roles = node.authenticate(&guard).await?;
    let _tunnel = node.open_tunnel(guard, "postgres").await?;
    Ok(())
}
```

Deux consommateurs réels de cette API dans ce dépôt : le démon
[`nux-cli`](../nux-cli) (usage direct, un seul Guard/Client par process) et
[`nux_gateway`](../../nux_gateway) (un nœud Guard embarqué derrière une API
REST). Les deux valent la peine d'être lus comme exemples d'intégration.

## Modules

| Module | Rôle |
|---|---|
| [`builder`] (`NuxNodeBuilder`) | Construction fluide de la pile réseau (tokio + TCP/Noise/Yamux + QUIC + relay-client + DCUtR) |
| [`node`] (`NuxNode`) | `authenticate()`, `run_guard*()`, `open_tunnel()`, boucle d'événements du swarm |
| [`auth`] | Challenge-response Ed25519, `Whitelist` (temps constant), `GuardAuthenticator`, anti-rejeu (±5 s) |
| [`tunnel`] | `TunnelRegistry` (services exposés, rôles requis, plafonds anti-amplification), relais de flux TCP/Unix |
| [`rate_limit`] | Cadence de connexions entrantes par IP, appliquée avant le handshake Noise |
| [`identity`] | Clés Ed25519 : fichier `0600` ou variable d'environnement, effacement mémoire (`zeroize`) |
| [`attestation`] | Empreinte SHA-256 du binaire appelant, vérifiée par le Guard (best-effort, opt-in par pair) |
| [`hardening`] | Durcissement anti-ptrace / anti-core-dump du processus au démarrage |
| [`protocol`] | Messages et codec `bincode` borné (`/nux/auth/1.0.0` + `/nux/tunnel/1.0.0`) |
| [`metrics`] | Compteurs internes (authentifications, tunnels, octets relayés), à exporter par l'appelant |

## Modèle de menace (résumé)

La frontière de confiance est le **compte OS**, pas le processus : un
attaquant qui contrôle l'UID exécutant le démon se sert de la vraie
identité, la crypto ne le lui interdit pas — voir
[`hardening`] pour ce que le durcissement anti-ptrace couvre (et ne couvre
pas). Détail complet, y compris les limites du relay `nux-relay` et de la
découverte par namespace, dans le
[README racine, section « Modèle de menace »](../../README.md#modèle-de-menace--ce-qui-nest-pas-couvert).

## Tests

```bash
cargo test -p nux-core          # unitaires + intégration réseau (tests/, nœuds réels en mémoire)
cargo +nightly fuzz run decode_request   # depuis fuzz/ — idem decode_response, decode_tunnel_header
```

`unsafe_code = "deny"` et `clippy::all = "deny"` au niveau du workspace :
zéro `unsafe`, zéro avertissement clippy toléré.

## Licence

MIT OR Apache-2.0, voir le [README racine](../../README.md).
