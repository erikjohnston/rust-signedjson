pub mod signatures;

use indolentjson::compact::compact as compact_json;

use serde::Serialize;
use serde_json;

pub fn canonicalize(bytes: &[u8]) -> serde_json::Result<Vec<u8>> {
    let val: serde_json::Value = try!(serde_json::from_slice(bytes));
    encode_canonically(&val)
}

pub fn encode_canonically<S: Serialize>(st: &S) -> serde_json::Result<Vec<u8>> {
    let mut val: serde_json::Value = serde_json::to_value(st);

    if let Some(obj) = val.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }

    // TODO: Assumes BTreeMap is serialized in key order
    let uncompact = try!(serde_json::to_vec(&val));

    let mut new_vec = Vec::with_capacity(uncompact.len());
    compact_json(&uncompact, &mut new_vec).expect("Invalid JSON");

    Ok(new_vec)
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn canonical() {
        let bytes = br#"{"old_verify_keys":{},"server_name":"jki.re","signatures":{"jki.re":{"ed25519:auto":"X2t7jN0jaJsiZWp57da9GqmQ874QFbukCMSqc5VclaB+2n4i8LPcZDkD6+fzg4tkfpSsiIDogkY4HWv1cnGhAg"}},"tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#;
        let canonical = canonicalize(bytes).unwrap();

        assert_eq!(&canonical[..], &br#"{"old_verify_keys":{},"server_name":"jki.re","tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#[..]);
    }

    #[test]
    fn encode_canonical() {
        let bytes = br#"{"old_verify_keys":{},"server_name":"jki.re","signatures":{"jki.re":{"ed25519:auto":"X2t7jN0jaJsiZWp57da9GqmQ874QFbukCMSqc5VclaB+2n4i8LPcZDkD6+fzg4tkfpSsiIDogkY4HWv1cnGhAg"}},"tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#;
        let deser: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let canonical = encode_canonically(&deser).unwrap();

        assert_eq!(&canonical[..], &br#"{"old_verify_keys":{},"server_name":"jki.re","tls_fingerprints":[{"sha256":"Big0aXVWZ/m0oEcHddgP4hTriTEvb4Jx6592W1mB5i4"}],"valid_until_ts":1462110302047,"verify_keys":{"ed25519:auto":{"key":"Sr/Vj3FIqyQ2WjJ9fWpUXRdz6fX4oFAjKrDmu198PnI"}}}"#[..]);
    }
}
