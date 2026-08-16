//! Fuzzing du décodage de l'en-tête d'ouverture de tunnel (`TunnelHeader`,
//! Phase 3) — premier message qu'un Guard lit sur un flux tunnel entrant.

#![no_main]

use nux_core::protocol::{TunnelHeader, decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = decode::<TunnelHeader>(data) {
        let bytes = encode(&header).expect("un en-tête décodé doit se réencoder");
        let back: TunnelHeader = decode(&bytes).expect("le réencodage doit se relire");
        assert_eq!(header, back, "aller-retour filaire non idempotent");
    }
});
