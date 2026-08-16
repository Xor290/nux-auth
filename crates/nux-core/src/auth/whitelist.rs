//! Liste blanche des pairs autorisés (`PeerId` → rôles).

use constant_time_eq::constant_time_eq;
use libp2p::PeerId;

/// Liste blanche : associe chaque `PeerId` autorisé à ses rôles.
///
/// La consultation ([`Whitelist::roles`]) parcourt systématiquement TOUTES
/// les entrées et compare les identités octet à octet via `constant_time_eq`
/// (cadrage §3.2) : le temps de réponse ne dépend ni de la présence du pair
/// ni de sa position dans la liste, neutralisant les attaques temporelles
/// visant à cartographier la liste blanche.
#[derive(Debug, Default, Clone)]
pub struct Whitelist {
    entries: Vec<(PeerId, Vec<String>)>,
}

impl Whitelist {
    /// Liste blanche vide : aucun pair n'est admis.
    pub fn new() -> Self {
        Self::default()
    }

    /// Autorise un pair avec les rôles donnés. Si le pair figurait déjà dans
    /// la liste, ses rôles sont remplacés.
    pub fn allow<I, S>(&mut self, peer: PeerId, roles: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let roles: Vec<String> = roles.into_iter().map(Into::into).collect();
        // Opération d'administration locale : la recherche naïve est acceptable
        // ici, seul le chemin de consultation (`roles`) est sensible au timing.
        if let Some(entry) = self.entries.iter_mut().find(|(p, _)| *p == peer) {
            entry.1 = roles;
        } else {
            self.entries.push((peer, roles));
        }
        self
    }

    /// Retire un pair de la liste blanche.
    pub fn revoke(&mut self, peer: &PeerId) {
        self.entries.retain(|(p, _)| p != peer);
    }

    /// Rôles du pair, ou `None` s'il est inconnu. Parcours complet en temps
    /// constant : pas de sortie anticipée, comparaisons `constant_time_eq`.
    pub fn roles(&self, peer: &PeerId) -> Option<Vec<String>> {
        let needle = peer.to_bytes();
        let mut found: Option<usize> = None;
        for (index, (candidate, _)) in self.entries.iter().enumerate() {
            let bytes = candidate.to_bytes();
            let matches = bytes.len() == needle.len() && constant_time_eq(&bytes, &needle);
            if matches {
                found = Some(index);
            }
        }
        found.map(|index| self.entries[index].1.clone())
    }

    /// Nombre de pairs autorisés.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` si aucun pair n'est autorisé.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    fn peer() -> PeerId {
        identity::generate().public().to_peer_id()
    }

    #[test]
    fn lookup_known_and_unknown() {
        let (alice, bob, mallory) = (peer(), peer(), peer());
        let mut list = Whitelist::new();
        list.allow(alice, ["db-writer", "metrics"])
            .allow(bob, Vec::<String>::new());

        assert_eq!(
            list.roles(&alice),
            Some(vec!["db-writer".into(), "metrics".into()])
        );
        assert_eq!(list.roles(&bob), Some(Vec::new()));
        assert_eq!(list.roles(&mallory), None);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn allow_replaces_roles_and_revoke_removes() {
        let alice = peer();
        let mut list = Whitelist::new();
        list.allow(alice, ["reader"]);
        list.allow(alice, ["admin"]);
        assert_eq!(list.roles(&alice), Some(vec!["admin".into()]));
        assert_eq!(list.len(), 1);

        list.revoke(&alice);
        assert!(list.is_empty());
        assert_eq!(list.roles(&alice), None);
    }
}
