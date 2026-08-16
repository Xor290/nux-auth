//! Codec binaire du protocole d'authentification.
//!
//! Sérialisation `bincode` défensive : taille de message plafonnée à
//! [`MAX_MESSAGE_SIZE`] aussi bien à la lecture du flux (l'octet excédentaire
//! n'est jamais lu) qu'au décodage (limite bincode), et octets résiduels
//! rejetés. C'est cette surface qui sera soumise à `cargo-fuzz` (cadrage §4).

use super::{NuxRequest, NuxResponse};
use async_trait::async_trait;
use bincode::Options;
use futures::prelude::*;
use libp2p::StreamProtocol;
use libp2p::request_response;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io;

/// Taille maximale d'un message d'authentification sur le fil (64 KiB).
/// Les messages du handshake tiennent en quelques centaines d'octets ; toute
/// trame plus grosse est un abus et est tronquée puis rejetée.
pub const MAX_MESSAGE_SIZE: u64 = 64 * 1024;

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_limit(MAX_MESSAGE_SIZE)
        .reject_trailing_bytes()
}

/// Sérialise un message du protocole.
pub fn encode<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    bincode_options()
        .serialize(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Désérialise un message du protocole. Ne panique jamais sur une entrée
/// malformée : toute anomalie est convertie en `io::Error`.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    bincode_options()
        .deserialize(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Codec `request-response` de libp2p pour le protocole Nux.
#[derive(Debug, Clone, Default)]
pub struct NuxCodec;

impl NuxCodec {
    async fn read_bounded<T>(io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        // `take` garantit qu'un pair malveillant ne peut pas faire gonfler la
        // mémoire au-delà de la limite, quel que soit ce qu'il envoie.
        io.take(MAX_MESSAGE_SIZE + 1).read_to_end(&mut buf).await?;
        if buf.len() as u64 > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message au-delà de la taille maximale",
            ));
        }
        Ok(buf)
    }
}

#[async_trait]
impl request_response::Codec for NuxCodec {
    type Protocol = StreamProtocol;
    type Request = NuxRequest;
    type Response = NuxResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        decode(&Self::read_bounded(io).await?)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        decode(&Self::read_bounded(io).await?)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode(&req)?).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode(&resp)?).await
    }
}
