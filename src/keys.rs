use sodiumoxide::crypto::sign;

use rustc_serialize::base64::{FromBase64, ToBase64};

use UNPADDED_BASE64;
use signed::{AsCanonical, Signed, SignedMut};



#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey {
    /// Public part of ED25519 signing key
    pub public: sign::PublicKey,
    /// Secret part of ED25519 signing key
    pub secret: sign::SecretKey,
    /// A unique ID for this signing key.
    pub key_id: String,
}


#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerifyResult {
    Valid,
    Invalid,
    Unsigned,
}


impl SigningKey {
    /// Create the signing key from a standard ED25519 seed
    pub fn from_seed(seed: &[u8], key_id: String) -> Option<SigningKey> {
        if let Some(seed) = sign::Seed::from_slice(seed) {
            let (public, secret) = sign::keypair_from_seed(&seed);
            Some(SigningKey {
                public: public,
                secret: secret,
                key_id: key_id,
            })
        } else {
            None
        }
    }

    /// Return a unpadded base64 version of the public key.
    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }

    pub fn sign<T>(&self, entity: &str, obj: &mut T)
        where T: AsCanonical + SignedMut
    {
        let sig = sign::sign_detached(&obj.as_canonical(), &self.secret);
        obj.signatures_mut().add_signature(entity, &self.key_id, sig);
    }

    pub fn sign_detached<T>(&self, obj: &mut T) -> sign::Signature
        where T: AsCanonical
    {
        sign::sign_detached(&obj.as_canonical(), &self.secret)
    }

    pub fn verify<T>(&self, entity: &str, obj: &mut T) -> VerifyResult
        where T: AsCanonical + Signed
    {
        if let Some(sig) = obj.signatures().get_signature(entity, &self.key_id) {
            if sign::verify_detached(sig, &obj.as_canonical(), &self.public) {
                VerifyResult::Valid
            } else {
                VerifyResult::Invalid
            }
        } else {
            VerifyResult::Unsigned
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyKey {
    /// Public part of ED25519 signing key
    pub public: sign::PublicKey,
    /// A unique ID for this key.
    pub key_id: String,
}

impl VerifyKey {
    /// Create the verify key from bytes
    pub fn from_slice(slice: &[u8], key_id: String) -> Option<VerifyKey> {
        sign::PublicKey::from_slice(slice).map(|public_key| {
            VerifyKey {
                public: public_key,
                key_id: key_id,
            }
        })
    }

    /// Create the verfiy key from Base64 encoded bytes.
    pub fn from_b64(b64: &[u8], key_id: String) -> Option<VerifyKey> {
        b64.from_base64()
           .ok()
           .and_then(|slice| sign::PublicKey::from_slice(&slice))
           .map(|public_key| {
               VerifyKey {
                   public: public_key,
                   key_id: key_id,
               }
           })
    }

    pub fn from_signing_key(signing_key: &SigningKey) -> VerifyKey {
        VerifyKey {
            public: signing_key.public,
            key_id: signing_key.key_id.clone(),
        }
    }

    /// Return a unpadded base64 version of the public key.
    pub fn public_key_b64(&self) -> String {
        self.public.0.to_base64(UNPADDED_BASE64)
    }

    pub fn verify<T>(&self, entity: &str, obj: &T) -> VerifyResult
        where T: AsCanonical + Signed
    {
        if let Some(sig) = obj.signatures().get_signature(entity, &self.key_id) {
            if sign::verify_detached(sig, &obj.as_canonical(), &self.public) {
                VerifyResult::Valid
            } else {
                VerifyResult::Invalid
            }
        } else {
            VerifyResult::Unsigned
        }
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
        let key = VerifyKey::from_b64(key_b64, String::from("ed25519:auto")).unwrap();
        assert_eq!(key.verify("jki.re", &frozen), VerifyResult::Valid);
        assert_eq!(key.verify("example.com", &frozen), VerifyResult::Unsigned);

        let key2_b64 = b"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198Pna";
        let key2 = VerifyKey::from_b64(key2_b64, String::from("ed25519:auto")).unwrap();
        assert_eq!(key2.verify("jki.re", &frozen), VerifyResult::Invalid);
    }

    #[test]
    fn sign() {
        let seed = "YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1".from_base64().unwrap();
        let sig_key = SigningKey::from_seed(&seed, String::from("ed25519:1")).unwrap();

        let mut frozen: SimpleFrozen = FrozenStruct::from_slice(b"{}").unwrap();
        sig_key.sign("domain", &mut frozen);

        assert_eq!(
            &frozen.serialize().unwrap()[..],
            &br#"{"signatures":{"domain":{"ed25519:1":"K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"}}}"#[..]
        );
    }
}
