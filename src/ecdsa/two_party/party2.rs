use curv::{BigInt, elliptic::curves::{Point, Secp256k1, Scalar}};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_two, party_one};
use serde::{Serialize, Deserialize};

use super::{MasterKey2, Party2Public, party1::KeyGenParty1Message2};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage {
    pub partial_sig: party_two::PartialSig,
    pub second_message: party_two::EphKeyGenSecondMsg,
}

pub struct BlindedSignMessage {
    pub partial_sig: party_two::PartialBlindedSig,
    pub second_message: party_two::EphKeyGenSecondMsg,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Party2SecondMessage {
    pub key_gen_second_message: party_two::KeyGenSecondMsg,
}

impl MasterKey2 {
    pub fn set_master_key(
        chain_code: &BigInt,
        ec_key_pair_party2: &party_two::EcKeyPair,
        party1_second_message_public_share: &Point<Secp256k1>,
        paillier_public: &party_two::PaillierPublic,
    ) -> MasterKey2 {
        let party2_public = Party2Public {
            q: party_two::compute_pubkey(ec_key_pair_party2, party1_second_message_public_share),
            p2: ec_key_pair_party2.public_share.clone(),
            p1: party1_second_message_public_share.clone(),
            paillier_pub: paillier_public.ek.clone(),
            c_key: paillier_public.encrypted_secret_share.clone(),
        };
        let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
        MasterKey2 {
            public: party2_public,
            private: party2_private,
            chain_code: chain_code.clone(),
        }
    }

    pub fn key_gen_first_message() -> (party_two::KeyGenFirstMsg, party_two::EcKeyPair) {
        party_two::KeyGenFirstMsg::create()
    }

    // from predefined secret key
    pub fn key_gen_first_message_predefined(
        secret_share: &Scalar<Secp256k1>,
    ) -> (party_two::KeyGenFirstMsg, party_two::EcKeyPair) {
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(secret_share.clone())
    }

    pub fn key_gen_second_message(
        party_one_first_message: &party_one::KeyGenFirstMsg,
        party_one_second_message: &KeyGenParty1Message2,
        party_one_second_message_salt: &[u8]
    ) -> Result<(Party2SecondMessage, party_two::PaillierPublic), ()> {
        let paillier_encryption_key = party_one_second_message.ek.clone();
        let paillier_encrypted_share = party_one_second_message.c_key.clone();

        let party_two_second_message =
            party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message.ecdh_second_message,
            );

        let party_two_paillier = party_two::PaillierPublic {
            ek: paillier_encryption_key.clone(),
            encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        let pdl_verify = party_two::PaillierPublic::pdl_verify(
            &party_one_second_message.composite_dlog_proof,
            &party_one_second_message.pdl_statement,
            &party_one_second_message.pdl_proof,
            &party_two_paillier,
            &party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
        );

        let correct_key_verify = party_one_second_message
            .correct_key_proof
            .verify(&party_two_paillier.ek, party_one_second_message_salt);

        match pdl_verify {
            Ok(_proof) => match correct_key_verify {
                Ok(_proof) => match party_two_second_message {
                    Ok(t) => Ok((
                        Party2SecondMessage {
                            key_gen_second_message: t,
                        },
                        party_two_paillier,
                    )),
                    Err(_verify_com_and_dlog_party_one) => Err(()),
                },
                Err(_correct_key_error) => Err(()),
            },
            Err(_pdl_error) => Err(()),
        }
    }

    pub fn sign_first_message() -> (
        party_two::EphKeyGenFirstMsg,
        party_two::EphCommWitness,
        party_two::EphEcKeyPair,
    ) {
        party_two::EphKeyGenFirstMsg::create_commitments()
    }

    pub fn sign_second_message(
        &self,
        ec_key_pair_party2: &party_two::EphEcKeyPair,
        eph_comm_witness: party_two::EphCommWitness,
        eph_party1_first_message: &party_one::EphKeyGenFirstMsg,
        message: &BigInt,
    ) -> SignMessage {
        let eph_key_gen_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            eph_party1_first_message,
        )
        .expect("");

        let partial_sig = party_two::PartialSig::compute(
            &self.public.paillier_pub,
            &self.public.c_key,
            &self.private,
            &ec_key_pair_party2,
            &eph_party1_first_message.public_share,
            message,
        );
        SignMessage {
            partial_sig,
            second_message: eph_key_gen_second_message,
        }
    }

    pub fn sign_second_message_with_blinding_factor(
        &self,
        ec_key_pair_party2: &party_two::EphEcKeyPair,
        eph_comm_witness: party_two::EphCommWitness,
        eph_party1_first_message: &party_one::EphKeyGenFirstMsg,
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> BlindedSignMessage {
        let eph_key_gen_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
            eph_comm_witness,
            eph_party1_first_message,
        )
        .expect("");

        let partial_sig = party_two::PartialSig::compute_blinded(
            &self.public.paillier_pub,
            &self.public.c_key,
            &self.private,
            &ec_key_pair_party2,
            &eph_party1_first_message.public_share,
            message,
            blinding_factor
        );
        BlindedSignMessage {
            partial_sig,
            second_message: eph_key_gen_second_message,
        }
    }
}