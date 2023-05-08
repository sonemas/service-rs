//! Provides functionality for signing keys.
use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Write},
};

use ring::{
    error, rand,
    signature::{self, KeyPair},
};

/// A trait that all signing keys need to implement.
pub trait SigningKey {
    /// Signs the provided message and returns the signature or a KeyError.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;

    /// Verifies whether the message was signed by the signing key instance.
    fn has_signed(&self, message: &[u8], signature: &[u8]) -> bool;
}

#[derive(Debug)]
/// Custom errors for this package.
pub enum KeyError {
    RingUnspecifiedError(error::Unspecified),
    RingKeyRejected(error::KeyRejected),
    IoError(io::Error),
    InvalidDerFile,
}

impl From<error::Unspecified> for KeyError {
    fn from(err: error::Unspecified) -> Self {
        Self::RingUnspecifiedError(err)
    }
}

impl From<error::KeyRejected> for KeyError {
    fn from(err: error::KeyRejected) -> Self {
        Self::RingKeyRejected(err)
    }
}

impl From<io::Error> for KeyError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            KeyError::RingUnspecifiedError(err) => format!("{}", err),
            KeyError::RingKeyRejected(err) => format!("{}", err),
            KeyError::IoError(err) => format!("{}", err),
            KeyError::InvalidDerFile => "invalid .der file".to_string(),
        };
        write!(f, "{}", msg)
    }
}

impl Error for KeyError {}

/// A default signing key implementation using the Ed25519 algorithm.
pub struct Key {
    der_bytes: Vec<u8>,
}

impl Key {
    /// Returnes a newly initialized key.
    pub fn new() -> Result<Self, KeyError> {
        let rng = rand::SystemRandom::new();
        let der_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?
            .as_ref()
            .to_owned();

        Ok(der_bytes.into())
    }

    /// Returns a key from a .der file.
    pub fn open(filename: &str) -> Result<Self, KeyError> {
        let der_bytes = fs::read(filename)?[..].to_vec();
        Ok(der_bytes.into())
    }

    /// Saves a key as a .der file.
    pub fn save(&self, filename: &str) -> io::Result<()> {
        File::create(filename)?.write_all(self.der_bytes.as_ref())
    }
}

impl From<&[u8]> for Key {
    fn from(der_bytes: &[u8]) -> Self {
        Self {
            der_bytes: der_bytes.to_vec(),
        }
    }
}

impl From<Vec<u8>> for Key {
    fn from(der_bytes: Vec<u8>) -> Self {
        Self { der_bytes }
    }
}

impl SigningKey for Key {
    /// Signs the provided message and returns the signature or a KeyError.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(self.der_bytes.as_ref())?;
        Ok(key_pair.sign(message).as_ref().to_vec())
    }

    /// Verifies whether the message was signed by the signing key instance.
    fn has_signed(&self, message: &[u8], signature: &[u8]) -> bool {
        let key_pair = match signature::Ed25519KeyPair::from_pkcs8(self.der_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => return false,
        };

        let public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, key_pair.public_key().as_ref());

        public_key.verify(message, signature.as_ref()).is_ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_can_sign_and_verify() {
        const MESSAGE: &[u8] = b"This is a test message";
        let key = Key::new().expect("should be able to create new key");

        let signature = key.sign(MESSAGE).expect("should be able to sign message");

        assert!(key.has_signed(MESSAGE, &signature));
    }

    #[test]
    fn it_can_save_and_load_keys_from_file() {
        const MESSAGE: &[u8] = b"This is a test message";
        let orig_key = Key::new().expect("should be able to create new key");
        orig_key
            .save("/tmp/testkey.der")
            .expect("should be able to save key file");

        let key = Key::open("/tmp/testkey.der").expect("should be able to load key file");

        let signature = key.sign(MESSAGE).expect("should be able to sign message");

        assert!(key.has_signed(MESSAGE, &signature));
        _ = std::fs::remove_file("/tmp/testkey.der");
    }
}
