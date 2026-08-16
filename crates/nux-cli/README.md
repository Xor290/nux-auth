# nux-cli

Démon et outil en ligne de commande d'**Nux-Auth** — binaire `nux` :
`keygen | guard | client | sync-config`. Bâti sur [`nux-core`](../nux-core)
(la bibliothèque/moteur) ; ce crate ne fait qu'exposer ses fonctionnalités en
CLI, journaliser, et lire un fichier de configuration TOML côté Guard.
Présentation complète du produit (pitch, diagrammes, modèle de menace) dans
le [README racine](../../README.md), dont la section
[« Démarrage rapide »](../../README.md#démarrage-rapide) couvre le même
terrain avec plus de contexte — ce document sert de référence rapide aux
commandes.

## Installation

```bash
cargo build --release -p nux-cli   # binaire : target/release/nux
```

## Commandes

### `nux keygen`

Génère une identité Ed25519 et l'écrit dans un fichier (`0600`, refuse
d'écraser un fichier existant).

```bash
nux keygen --out node.key
```

### `nux guard`

Démarre un nœud Guard : écoute, liste blanche, services exposés et rate
limiting viennent entièrement du fichier de configuration (voir
[`guard.example.toml`](guard.example.toml)) — seule l'identité reste un flag
séparé, pour ne jamais la coucher dans un fichier versionnable.

```bash
nux guard --config guard.toml --identity node.key
# ou : NUX_IDENTITY_KEY=<hex> nux guard --config guard.toml
```

`kill -HUP <pid>` recharge la **liste blanche** (`[[allow]]`) à chaud, sans
redémarrage : un pair radié voit sa connexion coupée immédiatement, les
autres ne sont pas affectés. `listen`, `[rate_limit]`, `[[expose]]` et
`[[checksum_bin]]` ne sont pris en compte qu'au démarrage. Un fichier
invalide au rechargement est rejeté et journalisé, sans effet sur l'état
courant.

### `nux client`

Démarre un nœud Client et compose un Guard distant.

```bash
nux client --dial /ip4/203.0.113.10/tcp/4588 \
  --identity node.key \
  --forward 5432:postgres
```

| Flag | Rôle |
|---|---|
| `--dial` | Multiaddr du Guard, ou `discover:<namespace>@<rendezvous_multiaddr>` pour le retrouver par nom logique auprès d'un `nux-relay` (voir `namespace` dans `guard.toml`) |
| `--identity` | Fichier de clé ; à défaut, `NUX_IDENTITY_KEY` |
| `--forward PORT_LOCAL:SERVICE` | Écoute sur `127.0.0.1:PORT_LOCAL`, relayé vers le service exposé par le Guard. **Non authentifié localement** : tout process du système, quel que soit son utilisateur, peut s'y connecter. Répétable. |
| `--forward-unix CHEMIN:SERVICE:UID[,UID...]` (Unix) | Socket Unix `0600` ; la connexion n'est relayée que si l'UID du process pair (`SO_PEERCRED`, non falsifiable) figure dans la liste. Répétable. |

### `nux sync-config` (Unix)

Compagnon de poll : interroge périodiquement
[`nux_gateway`](../../nux_gateway) — à travers un tunnel `nux client
--forward PORT:gwapi-guard` déjà en place — pour la config de ce Guard, et
recharge `guard.toml` + `SIGHUP` le Guard dès qu'elle change, en réutilisant
le mécanisme de rechargement à chaud ci-dessus. Ne modifie que
`[rate_limit]`, `[[allow]]` et `[[checksum_bin]]` ; `listen`, `[[expose]]`,
`relay`, `namespace` et les commentaires de l'opérateur restent intacts.

```bash
nux sync-config --config guard.toml \
  --gateway-port 5433 \
  --uuid <PeerId de ce Guard> \
  --guard-pid $(pgrep -f 'nux guard') \
  --poll-secs 30
```

## Configuration Guard (`guard.toml`)

Voir [`guard.example.toml`](guard.example.toml) pour un exemple annoté
complet ; chargement et validation dans [`src/guard_config.rs`](src/guard_config.rs).

```toml
listen = "/ip4/0.0.0.0/tcp/4588"

[rate_limit]
max = 30
window_secs = 60
exempt = ["203.0.113.9"]

[[allow]]
peer = "12D3KooW..."
roles = ["db-writer", "metrics"]

[[expose]]
name = "postgres"
port = 5432
role = "db-writer"

[[checksum_bin]]
peer = "12D3KooW..."
sha256 = "..."

# Optionnels : relay = "..." / namespace = "..." — voir guard.example.toml
```

## Variables d'environnement

| Variable | Rôle |
|---|---|
| `NUX_IDENTITY_KEY` | Identité Ed25519 en hexadécimal ; repli si `--identity` est omis |
| `NUX_AUDIT_LOG_DIR` | Répertoire du journal d'audit JSON (`audit.jsonl`, rotation quotidienne), défaut `/var/log/nux`. Si indisponible (droits insuffisants), le démon démarre quand même — avertissement sur stderr, pas de journal d'audit dédié. |
| `RUST_LOG` | Filtre `tracing` standard pour le journal applicatif (défaut `info,nux=debug`) |

## Licence

MIT OR Apache-2.0, voir le [README racine](../../README.md).
