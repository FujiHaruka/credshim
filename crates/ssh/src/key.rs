use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use signature::Signer;
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

pub struct SigningKey {
    key: PrivateKey,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("the stored value is not an OpenSSH private key")]
    Unparseable,
    #[error("the stored key is passphrase-protected; credshim needs an unencrypted key")]
    Encrypted,
    #[error("the stored key is {0}; credshim signs only with Ed25519 keys")]
    Unsupported(String),
    #[error("could not encode the generated key")]
    Encoding,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.key.fingerprint(HashAlg::Sha256))
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    pub fn generate(comment: &str) -> Result<(SecretString, PublicKey), KeyError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).expect("the OS random number generator is unavailable");
        let key = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&seed)),
            comment,
        )
        .map_err(|_| KeyError::Encoding)?;
        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|_| KeyError::Encoding)?;
        Ok((SecretString::from(pem.as_str()), key.public_key().clone()))
    }

    pub fn from_secret(secret: &SecretString) -> Result<Self, KeyError> {
        let key =
            PrivateKey::from_openssh(secret.expose_secret()).map_err(|_| KeyError::Unparseable)?;
        if key.is_encrypted() {
            return Err(KeyError::Encrypted);
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(KeyError::Unsupported(key.algorithm().to_string()));
        }
        Ok(Self { key })
    }

    pub fn public(&self) -> &KeyData {
        self.key.public_key().key_data()
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, signature::Error> {
        self.key.try_sign(data)
    }
}
