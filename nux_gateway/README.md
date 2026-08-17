# nux_gateway

Passerelle entre le control plane dashboard ([`SaaS-NuxGrid`](../../SaaS-NuxGrid))
et les nœuds Nux (Guard/Client). `nux_gateway` est lui-même un **nœud Nux**
(il embarque `nux-core`, mode `Guard`) : un Guard ou un Client s'y connecte
exactement comme il se connecterait à n'importe quel autre Guard — tunnel
libp2p chiffré (Noise/Yamux), authentifié par challenge-response Ed25519,
liste blanche vérifiée en temps constant. Aucun nouveau protocole réseau : le
tunnel réinjecte simplement le flux vers une API REST locale (axum), qui
elle-même parle au dashboard en HTTP normal.

```
Guard/Client --(tunnel libp2p, --forward N:gwapi-*)--> nux_gateway --(HTTP)--> SaaS-NuxGrid
                                                            ^
                                                            |
                                                  SaaS-NuxGrid (HTTP direct, PUT /configs)
```

## Trois surfaces

1. **Réseau (`NUX_GW_ADMIN_ADDR`)** — appelée directement par le dashboard.
   - `PUT /api/v1/configs/:uuid` (jeton `NUX_GW_ADMIN_TOKEN`) : pousse la
     config d'un Guard (rate limit, liste blanche, empreintes attendues) dans
     le cache SQLite local, et met à jour **à chaud** la liste blanche vive du
     nœud (`GuardControl::Allow`) — inutile de redémarrer la Gateway.
   - `GET /healthz` (public) : santé locale + sonde dashboard best-effort.

2. **Tunnel, rôle `gw-guard`, port loopback `NUX_GW_GUARD_PORT`** — réservé au
   Guard lui-même (son propre `uuid`, qui est son `PeerId`).
   - `GET /api/v1/configs/:uuid` : relit sa config — c'est cette route que
     `nux sync-config` (côté `nux-cli`, voir [README racine §6](../README.md#6-synchroniser-la-configuration-depuis-un-control-plane-dashboard-optionnel))
     interroge périodiquement pour recharger `guard.toml` à chaud, sans
     redémarrage.
   - `POST /api/v1/nodes/:peer_id/state` : relaie un changement d'état.

3. **Tunnel, rôle `gw-client`, port loopback `NUX_GW_CLIENT_PORT`** — ouvert à
   tout pair qu'un Guard autorise (`allow[].peer`).
   - `POST /api/v1/device/code`, `GET /api/v1/device/status`,
     `GET /api/v1/keys/public.pem` : proxy borné (chemins fixes, aucun header
     client transmis) vers les routes publiques du dashboard.
   - `POST /api/v1/nodes/:peer_id/state` : idem ci-dessus.

Un pair sans le rôle requis ne peut **pas ouvrir le tunnel du tout** —
protection au niveau du transport, avant même que le premier octet HTTP ne
soit émis.

## Configuration (`.env`, voir `.env.example`)

| Variable | Rôle |
|---|---|
| `DATABASE_URL` | Fichier SQLite du cache de configs |
| `NUX_GW_ADMIN_ADDR` | Bind réseau pour le dashboard (défaut `0.0.0.0:8088`) |
| `NUX_GW_ADMIN_TOKEN` | Jeton bearer admin (≥16 car., sinon échec au démarrage) |
| `NUX_GW_LISTEN` | Multiaddr d'écoute libp2p (défaut `/ip4/0.0.0.0/tcp/4589`) |
| `NUX_GW_IDENTITY_FILE` | Fichier d'identité Ed25519 ; à défaut `NUX_IDENTITY_KEY` (hex) |
| `NUX_GW_GUARD_PORT` / `NUX_GW_CLIENT_PORT` | Ports loopback réinjectés par le tunnel (jamais à exposer au réseau) |
| `NUX_GW_API_URL` | Base URL de l'API dashboard |
| `NUX_GW_DASHBOARD_TOKEN` | Jeton d'accès dashboard (rôle `technical`) pour le relais d'état ; absent → 503 |

## Limites connues (sécurité v1)

- **BOLA sur `gw-guard`** : le rôle n'est pas scopé par `uuid` — tout Guard
  authentifié peut lire la config ou relayer l'état d'un `uuid` qui n'est pas
  le sien. Cause racine : le relais TCP générique de `nux-core`
  (`TunnelRegistry` → `127.0.0.1:port`) ne transmet aucune information de
  `PeerId` à la couche HTTP, donc rien ici ne peut distinguer un appelant
  d'un autre. Mitigation v2 envisagée : un service de tunnel **et un port**
  dédiés par `uuid` (`TunnelRegistry::expose` par pair), au prix d'un cycle de
  vie plus complexe (ouverture/fermeture dynamique à chaque `PUT /configs`,
  ce qui suppose de rendre le `TunnelRegistry` mutable à chaud côté
  `nux-core`). **Mitigation v1 en place** en attendant : `GET
  /configs/:uuid` et `POST /nodes/:peer_id/state` sont journalisés à chaque
  appel (`tracing`) et soumis à une cadence globale (`src/rate_limit.rs`,
  120 requêtes/minute par défaut, partagée entre les ports `gw-guard` et
  `gw-client` pour la route d'état) — ça ne prouve aucune identité, ça borne
  seulement le débit d'une énumération ou d'une usurpation automatisées.
- **`NUX_GW_DASHBOARD_TOKEN` non renouvelé automatiquement** : c'est un access
  token dashboard classique (TTL court, `NUX_ACCESS_TTL`), pas un secret
  machine longue durée — à faire tourner par l'opérateur tant qu'aucun flux
  de renouvellement n'est câblé ici.
- Pas de rate limiting général sur l'API REST de la Gateway (au-delà du rate
  limiting par IP déjà appliqué par `nux-core` sur les connexions entrantes
  du nœud lui-même, et de la cadence ciblée du point précédent) — les routes
  d'appairage (`/device/code`, `/device/status`, `/keys/public.pem`) restent
  sans limite dédiée ; risque accepté pour ce MVP.
