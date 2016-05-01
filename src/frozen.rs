use std::borrow::Cow;
use std::fmt::Debug;
use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_json;

use ser::canonicalize;


use signed::{AsCanonical, GetUnsigned, Signed, SignedMut, Signatures, SignaturesMut};


#[derive(Debug)]
pub struct FrozenStruct<'a, T: Debug + Signed + SignedMut, U: Debug + Serialize + Deserialize> {
    parsed: T,
    serialized: Option<Cow<'a, [u8]>>,
    canonical: Cow<'a, [u8]>,
    unsigned: Option<U>,
}

impl<'a, T> FrozenStruct<'a, T, serde_json::Value>
    where T: Debug + Signed + SignedMut + AsCanonical + GetUnsigned
{
    pub fn wrap(mut wrapped: T) -> FrozenStruct<'a, T, serde_json::Value> {
        wrapped.signatures_mut().clear();
        FrozenStruct {
            canonical: Cow::Owned(wrapped.as_canonical().into_owned()),
            unsigned: wrapped.get_unsigned(),
            parsed: wrapped,
            serialized: None,
        }
    }
}

impl<'a, T, U> FrozenStruct<'a, T, U>
    where T: Debug + Signed + SignedMut + Deserialize,
          U: Debug + Serialize + Deserialize
{
    pub fn from_slice(bytes: &'a [u8]) -> Result<FrozenStruct<'a, T, U>, serde_json::Error> {
        let mut val: serde_json::Value = try!(serde_json::from_slice(bytes));
        let unsigned = if let Some(obj) = val.as_object_mut() {
            if let Some(val) = obj.remove("unsigned") {
                Some(try!(serde_json::from_value(val)))
            } else {
                None
            }
        } else {
            None
        };
        Ok(FrozenStruct {
            parsed: try!(serde_json::from_value(val)),
            serialized: Some(Cow::Borrowed(bytes)),
            canonical: Cow::Owned(try!(canonicalize(bytes))),
            unsigned: unsigned,
        })
    }
}

impl<'a, T, U> Deref for FrozenStruct<'a, T, U>
    where T: Debug + Signed + SignedMut,
          U: Debug + Serialize + Deserialize
{
    type Target = T;

    fn deref(&self) -> &T {
        &self.parsed
    }
}

impl<'a, T, U> Signed for FrozenStruct<'a, T, U>
    where T: Signed + Debug + Signed + SignedMut,
          U: Debug + Serialize + Deserialize
{
    fn signatures(&self) -> &Signatures {
        self.parsed.signatures()
    }
}

impl<'a, T, U> SignedMut for FrozenStruct<'a, T, U>
    where T: SignedMut + Debug + Signed + SignedMut,
          U: Debug + Serialize + Deserialize
{
    fn signatures_mut(&mut self) -> &mut SignaturesMut {
        self.serialized = None;
        self.parsed.signatures_mut()
    }
}

impl<'a, T, U> AsCanonical for FrozenStruct<'a, T, U>
    where T: Debug + Signed + SignedMut,
          U: Debug + Serialize + Deserialize
{
    fn as_canonical(&self) -> Cow<[u8]> {
        Cow::Borrowed(&self.canonical)
    }
}

impl<'a, T, U> Clone for FrozenStruct<'a, T, U>
    where T: Clone + Debug + Signed + SignedMut,
          U: Clone + Debug + Serialize + Deserialize
{
    fn clone(&self) -> Self {
        FrozenStruct {
            parsed: self.parsed.clone(),
            serialized: self.serialized.clone(),
            canonical: self.canonical.clone(),
            unsigned: self.unsigned.clone(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use signed::{Signed, Signatures, SimpleSigned, AsCanonical};
    use sodiumoxide::crypto::sign;
    use serde_json::Value;

    #[test]
    fn from_slice() {
        let bytes = br#"{"old_verify_keys":{},"server_name":"jki.re","signatures":{"jki.re":{"ed25519:auto":"X2t7jN0jaJsiZWp57da9GqmQ874QFbukCMSqc5VclaB+2n4i8LPcZDkD6+fzg4tkfpSsiIDogkY4HWv1cnGhAg"}},"tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#;
        let frozen: FrozenStruct<SimpleSigned, Value> = FrozenStruct::from_slice(bytes).unwrap();

        assert_eq!(&frozen.as_canonical()[..], &br#"{"old_verify_keys":{},"server_name":"jki.re","tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#[..]);

        let sig = frozen.signatures().get_signature("jki.re", "ed25519:auto").unwrap();

        let expected_sig_bytes = b"_k{\x8c\xdd#h\x9b\"ejy\xed\xd6\xbd\x1a\xa9\x90\xf3\xbe\x10\x15\xbb\xa4\x08\xc4\xaas\x95\\\x95\xa0~\xda~\"\xf0\xb3\xdcd9\x03\xeb\xe7\xf3\x83\x8bd~\x94\xac\x88\x80\xe8\x82F8\x1dk\xf5rq\xa1\x02";
        let expected_sig = sign::Signature::from_slice(expected_sig_bytes).unwrap();
        assert_eq!(sig, &expected_sig);
    }
}
