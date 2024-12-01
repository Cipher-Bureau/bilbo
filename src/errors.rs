use openssl::error::ErrorStack;
use ping::Error;
use std::{io, str::Utf8Error};
use thiserror::Error;

/// BilboError describes and wraps around all other errors.
///
#[derive(Error, Debug)]
pub enum BilboError {
    #[error("Shamirs Secret Sharing failed with message: {0}")]
    ShamirsError(#[from] shamirss::errors::SSSError),
    #[error("Ping failed with message: {0}")]
    PingErrro(#[from] Error),
    #[error("IO failed with message: {0}")]
    IoErrro(#[from] io::Error),
    #[error("Utf8 failed with message {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("Openssl failed with message: {0}")]
    OpensslStackError(#[from] ErrorStack),
    #[error("Bilbo failed with message: {0}")]
    GenericError(String),
}

impl From<BilboError> for std::io::Error {
    #[inline(always)]
    fn from(value: BilboError) -> Self {
        Self::new(io::ErrorKind::Other, format!("{value}"))
    }
}
