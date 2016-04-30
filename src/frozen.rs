use std::borrow::Cow;
use std::fmt::Debug;
use std::ops::Deref;

use serde::Deserialize;
use serde_json;

use ser::canonicalize;


use signed::{ToCanonical, Signed, SignedMut, Signatures, SignaturesMut};


#[derive(Debug)]
pub struct FrozenStruct<T: Debug + Signed + SignedMut> {
    inner: T,
    canonical: Vec<u8>,
}

impl<T> FrozenStruct<T>
    where T: Debug + Signed + SignedMut + ToCanonical
{
    pub fn wrap(mut inner: T) -> FrozenStruct<T> {
        inner.signatures_mut().clear();
        FrozenStruct {
            canonical: inner.to_canonical().into_owned(),
            inner: inner,
        }
    }
}

impl<T> FrozenStruct<T>
    where T: Debug + Signed + SignedMut + Deserialize
{
    pub fn from_slice(bytes: &[u8]) -> Result<FrozenStruct<T>, serde_json::Error> {
        Ok(FrozenStruct {
            inner: try!(serde_json::from_slice(bytes)),
            canonical: try!(canonicalize(&bytes)),
        })
    }
}

impl<T> FrozenStruct<T>
    where T: Debug + Signed + SignedMut
{
    pub unsafe fn from_raw_parts(inner: T, canonical: Vec<u8>) -> FrozenStruct<T> {
        FrozenStruct {
            inner: inner,
            canonical: canonical,
        }
    }
}

impl<T> Deref for FrozenStruct<T>
    where T: Debug + Signed + SignedMut
{
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> Signed for FrozenStruct<T>
    where T: Signed + Debug + Signed + SignedMut
{
    fn signatures(&self) -> &Signatures {
        self.inner.signatures()
    }
}

impl<T> SignedMut for FrozenStruct<T>
    where T: SignedMut + Debug + Signed + SignedMut
{
    fn signatures_mut(&mut self) -> &mut SignaturesMut {
        self.inner.signatures_mut()
    }
}

impl<T> ToCanonical for FrozenStruct<T>
    where T: Debug + Signed + SignedMut
{
    fn to_canonical(&self) -> Cow<[u8]> {
        Cow::Borrowed(&self.canonical)
    }
}

impl<T> Clone for FrozenStruct<T>
    where T: Clone + Debug + Signed + SignedMut
{
    fn clone(&self) -> Self {
        FrozenStruct {
            inner: self.inner.clone(),
            canonical: self.canonical.clone(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use signed::{Signed, Signatures, SimpleSigned, ToCanonical};
    use sodiumoxide::crypto::sign;

    #[test]
    fn from_slice() {
        let bytes = br#"{"old_verify_keys":{},"server_name":"jki.re","signatures":{"jki.re":{"ed25519:auto":"X2t7jN0jaJsiZWp57da9GqmQ874QFbukCMSqc5VclaB+2n4i8LPcZDkD6+fzg4tkfpSsiIDogkY4HWv1cnGhAg"}},"tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#;
        let frozen: FrozenStruct<SimpleSigned> = FrozenStruct::from_slice(bytes).unwrap();

        assert_eq!(&frozen.to_canonical()[..], &br#"{"old_verify_keys":{},"server_name":"jki.re","tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#[..]);

        let sig = frozen.signatures().get_signature("jki.re", "ed25519:auto").unwrap();

        let expected_sig_bytes = b"_k{\x8c\xdd#h\x9b\"ejy\xed\xd6\xbd\x1a\xa9\x90\xf3\xbe\x10\x15\xbb\xa4\x08\xc4\xaas\x95\\\x95\xa0~\xda~\"\xf0\xb3\xdcd9\x03\xeb\xe7\xf3\x83\x8bd~\x94\xac\x88\x80\xe8\x82F8\x1dk\xf5rq\xa1\x02";
        let expected_sig = sign::Signature::from_slice(expected_sig_bytes).unwrap();
        assert_eq!(sig, &expected_sig);
    }
}
