use curv::{elliptic::curves::{Point, Secp256k1}, BigInt};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use paillier::EncryptionKey;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Party1Public {
    pub q: Point<Secp256k1>,
    pub p1: Point<Secp256k1>,
    pub p2: Point<Secp256k1>,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct MasterKey1 {
    pub public: Party1Public,
    // Why is the field below public? See: https://github.com/KZen-networks/kms-secp256k1/issues/20
    pub private: party_one::Party1Private,
    chain_code: BigInt,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Party2Public {
    pub q: Point<Secp256k1>,
    pub p2: Point<Secp256k1>,
    pub p1: Point<Secp256k1>,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct MasterKey2 {
    pub public: Party2Public,
    pub private: party_two::Party2Private,
    pub chain_code: BigInt,
}

pub mod party1;
pub mod party2;

