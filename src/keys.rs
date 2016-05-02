use sodiumoxide::crypto::sign;

use rustc_serialize::base64::{FromBase64, ToBase64};

use UNPADDED_BASE64;
use signed::{AsCanonical, Signed, SignedMut};


pub trait PublicKey {
    fn public_key(&self) -> &sign::PublicKey;

    fn verify_detached<T>(&self, sig: &sign::Signature, obj: &T) -> VerifyResultDetached
        where T: AsCanonical
    {
        if sign::verify_detached(sig, &obj.as_canonical(), self.public_key()) {
            VerifyResultDetached::Valid
        } else {
            VerifyResultDetached::Invalid
        }
    }
}

pub trait SecretKey {
    fn secret_key(&self) -> &sign::SecretKey;

    fn sign_detached<T>(&self, obj: &T) -> sign::Signature
        where T: AsCanonical
    {
        sign::sign_detached(&obj.as_canonical(), &self.secret_key())
    }
}

pub trait NamedKey {
    fn entity(&self) -> &str;
    fn key_id(&self) -> &str;
}

pub trait NamedPublicKey: PublicKey + NamedKey {
    fn verify<T>(&self, obj: &T) -> VerifyResult
        where T: AsCanonical + Signed
    {
        if let Some(sig) = obj.signatures().get_signature(self.entity(), self.key_id()) {
            if sign::verify_detached(sig, &obj.as_canonical(), self.public_key()) {
                VerifyResult::Valid
            } else {
                VerifyResult::Invalid
            }
        } else {
            VerifyResult::Unsigned
        }
    }
}

impl<T> NamedPublicKey for T where T: PublicKey + NamedKey {}

pub trait NamedSecretKey: SecretKey + NamedKey {
    fn sign<T>(&self, obj: &mut T)
        where T: AsCanonical + SignedMut
    {
        let sig = sign::sign_detached(&obj.as_canonical(), self.secret_key());
        obj.signatures_mut().add_signature(self.entity(), self.key_id(), sig);
    }
}

impl<T> NamedSecretKey for T where T: SecretKey + NamedKey {}


impl PublicKey for sign::PublicKey {
    fn public_key(&self) -> &sign::PublicKey {
        &self
    }
}

impl SecretKey for sign::SecretKey {
    fn secret_key(&self) -> &sign::SecretKey {
        &self
    }
}


#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerifyResult {
    Valid,
    Invalid,
    Unsigned,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerifyResultDetached {
    Valid,
    Invalid,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyPair {
    /// Public part of ED25519 signing key
    pub public: sign::PublicKey,
    /// Secret part of ED25519 signing key
    pub secret: sign::SecretKey,
    /// A unique ID for this signing key.
    pub key_id: String,
    pub entity: String,
}


impl SigningKeyPair {
    /// Create the signing key from a standard ED25519 seed
    pub fn from_seed<E, K>(seed: &[u8], entity: E, key_id: K) -> Option<SigningKeyPair>
        where E: Into<String>,
              K: Into<String>
    {
        if let Some(seed) = sign::Seed::from_slice(seed) {
            let (public, secret) = sign::keypair_from_seed(&seed);
            Some(SigningKeyPair {
                public: public,
                secret: secret,
                key_id: key_id.into(),
                entity: entity.into(),
            })
        } else {
            None
        }
    }

    /// Return a unpadded base64 version of the public key.
    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }
}

impl NamedKey for SigningKeyPair {
    fn entity(&self) -> &str {
        &self.entity
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl SecretKey for SigningKeyPair {
    fn secret_key(&self) -> &sign::SecretKey {
        &self.secret
    }
}

impl PublicKey for SigningKeyPair {
    fn public_key(&self) -> &sign::PublicKey {
        &self.public
    }
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyKey {
    /// Public part of ED25519 signing key
    pub public: sign::PublicKey,
    /// A unique ID for this key.
    pub key_id: String,
    pub entity: String,
}

impl VerifyKey {
    /// Create the verify key from bytes
    pub fn from_slice<E, K>(slice: &[u8], entity: E, key_id: K) -> Option<VerifyKey>
        where E: Into<String>,
              K: Into<String>
    {
        sign::PublicKey::from_slice(slice).map(|public_key| {
            VerifyKey {
                public: public_key,
                entity: entity.into(),
                key_id: key_id.into(),
            }
        })
    }

    /// Create the verfiy key from Base64 encoded bytes.
    pub fn from_b64<E, K>(b64: &[u8], entity: E, key_id: K) -> Option<VerifyKey>
        where E: Into<String>,
              K: Into<String>
    {
        b64.from_base64()
           .ok()
           .and_then(|slice| sign::PublicKey::from_slice(&slice))
           .map(|public_key| {
               VerifyKey {
                   public: public_key,
                   entity: entity.into(),
                   key_id: key_id.into(),
               }
           })
    }

    pub fn from_signing_key(signing_key: &SigningKeyPair) -> VerifyKey {
        VerifyKey {
            public: signing_key.public,
            entity: signing_key.entity.clone(),
            key_id: signing_key.key_id.clone(),
        }
    }

    /// Return a unpadded base64 version of the public key.
    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }
}

impl NamedKey for VerifyKey {
    fn entity(&self) -> &str {
        &self.entity
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl PublicKey for VerifyKey {
    fn public_key(&self) -> &sign::PublicKey {
        &self.public
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use signed::SimpleSigned;
    use serde_json::Value;
    use frozen::FrozenStruct;
    use rustc_serialize::base64::FromBase64;

    type SimpleFrozen<'a> = FrozenStruct<'a, SimpleSigned, Value>;

    #[test]
    fn verify() {
        let bytes = br#"{"old_verify_keys":{},"server_name":"jki.re","signatures":{"jki.re":{"ed25519:auto":"X2t7jN0jaJsiZWp57da9GqmQ874QFbukCMSqc5VclaB+2n4i8LPcZDkD6+fzg4tkfpSsiIDogkY4HWv1cnGhAg"}},"tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#;
        let frozen: SimpleFrozen = FrozenStruct::from_slice(bytes).unwrap();

        let key_b64 = b"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI";
        let key = VerifyKey::from_b64(key_b64, "jki.re", "ed25519:auto").unwrap();
        let key2 = VerifyKey::from_b64(key_b64, "example.com", "ed25519:auto").unwrap();
        assert_eq!(key.verify(&frozen), VerifyResult::Valid);
        assert_eq!(key2.verify(&frozen), VerifyResult::Unsigned);

        let key3_b64 = b"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198Pna";
        let key3 = VerifyKey::from_b64(key3_b64, "jki.re", "ed25519:auto").unwrap();
        assert_eq!(key3.verify(&frozen), VerifyResult::Invalid);
    }

    #[test]
    fn sign() {
        let seed = "YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1".from_base64().unwrap();
        let sig_key = SigningKeyPair::from_seed(&seed, "domain", "ed25519:1").unwrap();

        let mut frozen: SimpleFrozen = FrozenStruct::from_slice(b"{}").unwrap();
        sig_key.sign(&mut frozen);

        assert_eq!(
            &frozen.serialize().unwrap()[..],
            &br#"{"signatures":{"domain":{"ed25519:1":"K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"}}}"#[..]
        );
    }
}
