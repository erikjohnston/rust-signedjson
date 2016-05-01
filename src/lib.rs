extern crate indolentjson;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;

#[cfg(test)]
extern crate itertools;

pub mod frozen;
pub mod keys;
pub mod ser;
pub mod signed;


use rustc_serialize::base64;


pub const UNPADDED_BASE64: base64::Config = base64::Config {
    char_set: base64::CharacterSet::Standard,
    newline: base64::Newline::LF,
    pad: false,
    line_length: None,
};
