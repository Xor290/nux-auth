# Nux-Auth

Tunnels applicatifs chiffrés et authentifiés entre serveurs, bâtis sur la
couche pair-à-pair de [`rust-libp2p`](https://libp2p.io/) — **sans VPN, sans
serveur SSO central**. Un service qui doit en joindre un autre (base de
données, cache, API interne…) n'ouvre plus un port réseau classique protégé
par mot de passe ou firewall à maintenir : il tend une clé publique.

## Pourquoi

Le modèle classique — port ouvert + mot de passe/IP autorisée, ou VPN
mutualisé — a deux défauts structurels : la surface d'attaque est visible
(un scan de port trouve le service, même protégé) et la confiance est
généralement mutualisée à l'échelle du VPN plutôt que par service. Nux
répond aux deux :

- **Identité = clé publique.** Chaque nœud est une paire de clés Ed25519 ;
  son `PeerId` en dérive. Pas de compte, pas de mot de passe, pas d'autorité
  centrale à qui faire confiance.
- **Silence radio.** Un pair non authentifié n'obtient jamais la moindre
  réponse distinctive : pas d'erreur « accès refusé », pas de bannière, pas
  de différence observable entre « port fermé » et « port existant mais
  accès refusé ». Le service est invisible tant qu'on ne prouve pas qui l'on
  est.

## Les trois piliers

- **SSO décentralisé** — l'identité d'un serveur est sa clé publique
  (`PeerId`) ; l'accès se prouve par un challenge-response Ed25519 (défi à
  usage unique, fenêtre anti-rejeu de ±5 s), validé localement par le Guard
  contre sa liste blanche, en temps constant.
- **Tunneling furtif** — le Client capture un flux TCP (ou socket Unix)
  local, l'encapsule de bout en bout avec Noise sur un flux Yamux dédié, et
  le Guard le réinjecte vers `127.0.0.1` côté service. Le trafic applicatif
  ne quitte jamais la boucle locale en clair.
- **Masquage de port** — face à un pair non authentifié ou non autorisé pour
  le service demandé, aucune erreur verbeuse ne quitte jamais le nœud : la
  connexion se coupe, silencieusement, c'est tout.

## Rôles

| Rôle | Ce qu'il fait |
|---|---|
| **Guard** | Protège une ressource locale (ex. PostgreSQL sur `127.0.0.1:5432`). Écoute, tient la liste blanche (`[[allow]]`, pair → rôles) et les services exposés (`[[expose]]`, service → rôle requis) — entièrement pilotés par `guard.toml`. |
| **Client** | Compose un Guard distant, s'authentifie, puis redirige un port local (`--forward`) ou une socket Unix (`--forward-unix`, restreinte par UID pair via `SO_PEERCRED`) vers un service exposé par ce Guard. |

Un même service peut avoir plusieurs Clients autorisés, avec des rôles
différents ; un Guard peut exposer plusieurs services derrière la même
liste blanche.

## Démarrage rapide

```bash
cargo build --release -p nux-cli   # binaire : target/release/nux
```

**Côté Guard** — générer une identité, écrire `guard.toml`, démarrer :

```bash
nux keygen --out node.key
# PeerId affiché : à donner au(x) Client(s) pour leur `--dial`,
# et à inscrire dans le guard.toml du CLIENT si lui aussi vérifie une liste blanche.
```

```toml
# guard.toml — voir crates/nux-cli/guard.example.toml pour un exemple annoté complet
listen = "/ip4/0.0.0.0/tcp/4588"

[rate_limit]
max = 30
window_secs = 60

[[allow]]
peer = "12D3KooW..."       # PeerId du Client
roles = ["db-writer"]

[[expose]]
name = "postgres"
port = 5432
role = "db-writer"
```

```bash
nux guard --config guard.toml --identity node.key
```

**Côté Client** — sa propre identité, puis dial + forward :

```bash
nux keygen --out client.key
nux client --dial /ip4/203.0.113.10/tcp/4588 \
  --identity client.key \
  --forward 5432:postgres
# psql -h 127.0.0.1 -p 5432 ... passe maintenant par le tunnel authentifié
```

`kill -HUP <pid guard>` recharge la liste blanche à chaud, sans couper les
pairs qui restent autorisés — voir le
[README de `nux-cli`](crates/nux-cli/README.md) pour le détail des
commandes, flags et variables d'environnement.

## Modèle de menace — ce qui est couvert, ce qui ne l'est pas

**Couvert :**

- Un attaquant réseau (passif ou actif) sans les clés privées légitimes ne
  peut ni lire le trafic (Noise), ni usurper une identité (signature
  Ed25519), ni même détecter qu'un service Nux écoute sur un port donné
  (silence radio face aux pairs non authentifiés).
- Un pair authentifié mais non autorisé pour un service donné (rôle absent
  de `[[allow]]`) voit son flux abandonné sans un octet — même traitement
  qu'un pair inconnu, pour ne pas distinguer « existe mais interdit » de
  « n'existe pas ».
- Une dérive de build accidentelle peut être détectée en best-effort par
  l'empreinte SHA-256 du binaire Client (`attestation`, opt-in par pair via
  `[[checksum_bin]]`) — pas une garantie face à un attaquant actif, qui peut
  simplement mentir sur son empreinte ; la preuve d'identité opposable
  reste la signature Ed25519.

**Non couvert :**

- **Le compte OS (UID), pas le processus, est la frontière de confiance.**
  Un attaquant qui contrôle l'UID exécutant le démon dispose de la vraie
  identité : il peut lire le fichier de clé `0600` dont il est propriétaire
  et lancer son propre Client, sans même toucher au processus en cours. Le
  durcissement anti-ptrace (`hardening`, non-dumpable au démarrage) relève
  le coût d'une inspection mémoire *du même UID* mais ne crée aucune
  frontière à l'intérieur d'un compte déjà compromis, et ne protège pas
  contre `root`. Pour une isolation réelle : utilisateur dédié non
  privilégié, séparé des applications servies.
- **Le port local forwardé (`--forward`) n'est pas authentifié.** Une fois
  le tunnel ouvert, tout process du système, quel que soit son utilisateur,
  peut s'y connecter — c'est le rôle de l'OS (pare-feu local, namespaces),
  pas de Nux. `--forward-unix` restreint par UID pair (`SO_PEERCRED`,
  non falsifiable) là où c'est possible (Unix).
- **La découverte par relay/namespace n'est pas un vecteur d'accès** : un
  point de rendezvous permet à un Client de retrouver l'adresse d'un Guard
  par un nom logique, ou à un Guard sans IP publique de rester joignable via
  un circuit relayé — dans les deux cas, l'authentification Ed25519 a lieu
  en bout de chaîne, exactement comme sur une adresse directe. Le relay ne
  déchiffre rien mais voit les métadonnées de connexion (qui parle à qui,
  quand) : à héberger sur une infrastructure de confiance équivalente à
  celle des Guards eux-mêmes.

Détail par module (limites précises, tests associés) dans les
`//!` doc-comments de [`nux-core`](crates/nux-core/src/lib.rs), notamment
[`hardening`](crates/nux-core/src/hardening.rs) et
[`attestation`](crates/nux-core/src/attestation.rs).

## Structure du dépôt

| Crate | Rôle |
|---|---|
| [`nux-core`](crates/nux-core) | Bibliothèque : identité, pile réseau libp2p (TCP/Noise/Yamux + QUIC + relay-client + DCUtR), authentification, tunneling, rate limiting, durcissement. |
| [`nux-cli`](crates/nux-cli) | Binaire `nux` : expose `nux-core` en ligne de commande (`keygen`, `guard`, `client`, `sync-config`), journalisation, lecture de `guard.toml`. |

## Tests

```bash
cargo test -p nux-core -p nux-cli
cargo +nightly fuzz run decode_request   # depuis crates/nux-core/fuzz/ — idem decode_response, decode_tunnel_header
```

`unsafe_code = "deny"` et `clippy::all = "deny"` au niveau du workspace :
zéro `unsafe`, zéro avertissement clippy toléré.

## Licence

MIT OR Apache-2.0, au choix.
