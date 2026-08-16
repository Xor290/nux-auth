//! Fuzzing du décodage des requêtes d'authentification (`NuxRequest`) :
//! aucune entrée ne doit paniquer, et tout message accepté doit survivre à
//! un aller-retour encode/decode à l'identique.

#![no_main]

use nux_core::protocol::{NuxRequest, decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = decode::<NuxRequest>(data) {
        let bytes = encode(&message).expect("un message décodé doit se réencoder");
        let back: NuxRequest = decode(&bytes).expect("le réencodage doit se relire");
        assert_eq!(message, back, "aller-retour filaire non idempotent");
    }
});
