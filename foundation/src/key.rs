use std::{error::Error, fmt, fs::{File, self}, io::{Write, self}};

use ring::{
    rand,
    signature::{self, KeyPair}, error,
};

pub trait SigningKey {
    fn sign(&self, message: &[u8]) -> Result<signature::Signature, KeyError>;
    fn verify_signature(message: &[u8], signature: &[u8]) -> bool;
    fn has_signed(&self, message: &[u8], signature: &[u8]) -> bool;
}

#[derive(Debug)]
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

pub struct Key {
    der_bytes: Vec<u8>,
}

impl Key{
    pub fn new() -> Result<Self, KeyError>  {
        let rng = rand::SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let der_bytes = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng)?.as_ref().to_vec();

        Ok(Self{der_bytes})
    }

    pub fn open(filename: &str) -> Result<Self, KeyError> {
        let der_bytes = fs::read(filename)?[..].to_vec();
        Ok(Self{der_bytes})
    }

    pub fn save(&self, filename: &str) -> io::Result<()> {
        File::create(filename)?.write_all(self.der_bytes.as_ref())
    }
}

impl SigningKey for Key {
    fn sign(&self, message: &[u8]) -> Result<signature::Signature, KeyError> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(self.der_bytes.as_ref())?;
        Ok(key_pair.sign(message))
    }

    fn verify_signature(message: &[u8], signature: &[u8]) -> bool {
        let public_key = 
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, signature);
        
        public_key.verify(message, signature).is_ok()
    }

    fn has_signed(&self, message: &[u8], signature: &[u8]) -> bool {
        let key_pair = match signature::Ed25519KeyPair::from_pkcs8(self.der_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key_pair.public_key().as_ref());

        public_key.verify(message, signature.as_ref()).is_ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_works() {
        todo!("Implement tests and comments")
    }

}
