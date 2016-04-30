extern crate indolentjson;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate sodiumoxide;

#[cfg(test)]
extern crate itertools;

pub mod frozen;
pub mod ser;
pub mod signed;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
