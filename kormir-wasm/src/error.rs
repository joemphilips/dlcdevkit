use kormir::error::Error;
use thiserror::Error;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Error, Debug, Clone)]
#[wasm_bindgen]
pub enum JsError {
    #[error("Invalid argument given")]
    InvalidArgument,
    #[error("Attempted to sign an event that was already signed")]
    EventAlreadySigned,
    #[error("Event data was not found")]
    NotFound,
    #[error("Storage failed to read/save the data")]
    StorageFailure,
    #[error("User gave an invalid outcome")]
    InvalidOutcome,
    #[error("Internal Error")]
    Internal,
    #[error("Error sending nostr events")]
    Nostr,
}

impl From<Error> for JsError {
    #[allow(deprecated)]
    fn from(value: Error) -> Self {
        match value {
            Error::InvalidArgument
            | Error::InvalidEventId
            | Error::InvalidOutcomes
            | Error::InvalidBase
            | Error::InvalidNumberOfDigits
            | Error::InvalidNonces
            | Error::InvalidEventDescriptor
            | Error::InvalidAnnouncement => Self::InvalidArgument,
            Error::EventAlreadySigned => Self::EventAlreadySigned,
            Error::NotFound => Self::NotFound,
            Error::StorageFailure => Self::StorageFailure,
            Error::InvalidOutcome => Self::InvalidOutcome,
            Error::Internal => Self::Internal,
        }
    }
}

impl From<JsError> for Error {
    #[allow(deprecated)]
    fn from(value: JsError) -> Self {
        match value {
            JsError::InvalidArgument => Self::InvalidArgument,
            JsError::EventAlreadySigned => Self::EventAlreadySigned,
            JsError::NotFound => Self::NotFound,
            JsError::StorageFailure => Self::StorageFailure,
            JsError::InvalidOutcome => Self::InvalidOutcome,
            JsError::Internal | JsError::Nostr => Self::Internal,
        }
    }
}

impl From<rexie::Error> for JsError {
    fn from(_: rexie::Error) -> Self {
        JsError::StorageFailure
    }
}

impl From<hex::FromHexError> for JsError {
    fn from(_: hex::FromHexError) -> Self {
        JsError::InvalidArgument
    }
}

impl From<nostr::key::Error> for JsError {
    fn from(_: nostr::key::Error) -> Self {
        JsError::InvalidArgument
    }
}

impl From<kormir::bitcoin::secp256k1::Error> for JsError {
    fn from(_: kormir::bitcoin::secp256k1::Error) -> Self {
        JsError::StorageFailure
    }
}

impl From<kormir::lightning::ln::msgs::DecodeError> for JsError {
    fn from(_: kormir::lightning::ln::msgs::DecodeError) -> Self {
        JsError::InvalidArgument
    }
}

impl From<serde_json::Error> for JsError {
    fn from(_: serde_json::Error) -> Self {
        JsError::StorageFailure
    }
}

impl From<nostr::event::builder::Error> for JsError {
    fn from(_: nostr::event::builder::Error) -> Self {
        JsError::NotFound
    }
}

impl From<nostr_sdk::client::Error> for JsError {
    fn from(_: nostr_sdk::client::Error) -> Self {
        JsError::Nostr
    }
}

impl From<gloo_utils::errors::JsError> for JsError {
    fn from(_: gloo_utils::errors::JsError) -> Self {
        JsError::StorageFailure
    }
}
