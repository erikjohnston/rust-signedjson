use std::borrow::Cow;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::Deref;

use serde;

use sodiumoxide::crypto::sign;

use ser::signatures::Base64Signature;


pub trait Signatures {
    fn get_signature(&self, entity: &str, key_id: &str) -> Option<&sign::Signature>;
    fn get_signatures_for_entity<'a>(
        &'a self,
        entity: &'a str
    ) -> Box<Iterator<Item = (&'a str, &sign::Signature)> + 'a>;
}

pub trait SignaturesMut {
    fn add_signature(&mut self, entity: &str, key_id: &str, sig: sign::Signature);
    fn clear(&mut self);
}

pub trait Signed {
    fn signatures(&self) -> &Signatures;
}

pub trait SignedMut: Signed {
    fn signatures_mut(&mut self) -> &mut SignaturesMut;
}

pub trait ToCanonical {
    fn to_canonical(&self) -> Cow<[u8]>;
}


impl<S> Signatures for BTreeMap<String, BTreeMap<String, S>>
    where S: Deref<Target = sign::Signature>
{
    fn get_signature(&self, entity: &str, key_id: &str) -> Option<&sign::Signature> {
        self.get(entity).and_then(|sigs| sigs.get(key_id)).map(|s| s.deref())
    }

    fn get_signatures_for_entity<'a>(
        &'a self,
        entity: &'a str
    ) -> Box<Iterator<Item = (&'a str, &sign::Signature)> + 'a> {
        Box::new(self.iter()
                     .filter_map(move |(d, sigs)| if d == entity {
                         Some(sigs)
                     } else {
                         None
                     })
                     .flat_map(|s| s.iter())
                     .map(|(k, v)| (&k[..], v.deref())))
    }
}

impl<S> SignaturesMut for BTreeMap<String, BTreeMap<String, S>>
    where S: From<sign::Signature>
{
    fn add_signature(&mut self, entity: &str, key_id: &str, sig: sign::Signature) {
        self.entry(entity.to_string())
            .or_insert_with(BTreeMap::new)
            .insert(key_id.to_string(), S::from(sig));
    }

    fn clear(&mut self) {
        self.clear();
    }
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimpleSigned {
    pub signatures: BTreeMap<String, BTreeMap<String, Base64Signature>>,
}

impl Signed for SimpleSigned {
    fn signatures(&self) -> &Signatures {
        &self.signatures
    }
}

impl SignedMut for SimpleSigned {
    fn signatures_mut(&mut self) -> &mut SignaturesMut {
        &mut self.signatures
    }
}


enum SimpleSignedField {
    SIGNATURES,
    IGNORE,
}
impl serde::de::Deserialize for SimpleSignedField {
    #[inline]
    fn deserialize<D>(deserializer: &mut D) -> Result<SimpleSignedField, D::Error>
        where D: serde::de::Deserializer
    {
        deserializer.deserialize_struct_field(SimpleSignedFieldVisitor::<D> {
            phantom: PhantomData,
        })
    }
}

struct SimpleSignedFieldVisitor<D> {
    phantom: PhantomData<D>,
}
impl<D> serde::de::Visitor for SimpleSignedFieldVisitor<D>
    where D: serde::de::Deserializer
{
    type Value = SimpleSignedField;

    fn visit_usize<E>(&mut self, value: usize) -> Result<SimpleSignedField, E>
        where E: serde::de::Error
    {
        match value {
            0usize => Ok(SimpleSignedField::SIGNATURES),
            _ => Ok(SimpleSignedField::IGNORE),
        }
    }
    fn visit_str<E>(&mut self, value: &str) -> Result<SimpleSignedField, E>
        where E: serde::de::Error
    {
        match value {
            "signatures" => Ok(SimpleSignedField::SIGNATURES),
            _ => Ok(SimpleSignedField::IGNORE),
        }
    }
    fn visit_bytes<E>(&mut self, value: &[u8]) -> Result<SimpleSignedField, E>
        where E: serde::de::Error
    {
        match value {
            b"signatures" => Ok(SimpleSignedField::SIGNATURES),
            _ => Ok(SimpleSignedField::IGNORE),
        }
    }
}

struct SimpleSignedVisitor<D: serde::de::Deserializer>(PhantomData<D>);
impl<D: serde::de::Deserializer> serde::de::Visitor for SimpleSignedVisitor<D> {
    type Value = SimpleSigned;

    #[inline]
    fn visit_seq<V>(&mut self, mut visitor: V) -> Result<SimpleSigned, V::Error>
        where V: serde::de::SeqVisitor
    {
        {
            let sigs = match try!(visitor.visit()) {
                Some(value) => value,
                None => {
                    return Err(serde::de::Error::end_of_stream());
                }
            };
            try!(visitor.end());
            Ok(SimpleSigned { signatures: sigs })
        }
    }
    #[inline]
    fn visit_map<V>(&mut self, mut visitor: V) -> Result<SimpleSigned, V::Error>
        where V: serde::de::MapVisitor
    {
        {
            let mut sigs = None;
            while let Some(key) = try!(visitor.visit_key()) {
                match key {
                    SimpleSignedField::SIGNATURES => {
                        sigs = Some(try!(visitor.visit_value()));
                    }
                    _ => {
                        try!(visitor.visit_value::<serde::de::impls::IgnoredAny>());
                    }
                }
            }
            let sigs = match sigs {
                Some(sigs) => sigs,
                None => {
                    match visitor.missing_field("signatures") {
                        Ok(value) => value,
                        Err(value) => return Err(value),
                    }
                }
            };
            try!(visitor.end());
            Ok(SimpleSigned { signatures: sigs })
        }
    }
}


impl serde::de::Deserialize for SimpleSigned {
    fn deserialize<D>(deserializer: &mut D) -> Result<SimpleSigned, D::Error>
        where D: serde::de::Deserializer
    {
        {
            const FIELDS: &'static [&'static str] = &["signatures"];
            deserializer.deserialize_struct("SimpleSigned",
                                            FIELDS,
                                            SimpleSignedVisitor::<D>(PhantomData))
        }
    }
}
