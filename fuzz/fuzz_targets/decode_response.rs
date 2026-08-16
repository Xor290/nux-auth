//! Fuzzing du décodage des réponses d'authentification (`NuxResponse`) —
//! ce que rencontre un Client face à un Guard hostile.

#![no_main]

use nux_core::protocol::{NuxResponse, decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = decode::<NuxResponse>(data) {
        let bytes = encode(&message).expect("un message décodé doit se réencoder");
        let back: NuxResponse = decode(&bytes).expect("le réencodage doit se relire");
        assert_eq!(message, back, "aller-retour filaire non idempotent");
    }
});
