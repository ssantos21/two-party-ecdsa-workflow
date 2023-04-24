use curv::{BigInt, elliptic::curves::{Point, Secp256k1}, cryptographic_primitives::proofs::sigma_dlog::DLogProof};
use multi_party_ecdsa::{protocols::two_party_ecdsa::lindell_2017::{party_one, party_two}, utilities::zk_pdl_with_slack::{PDLwSlackStatement, PDLwSlackProof}};
use paillier::EncryptionKey;
use serde::{Serialize, Deserialize};
use sha2::Sha256;
use zk_paillier::zkproofs::{CompositeDLogProof, NiCorrectKeyProof};

use crate::Errors;

use super::{MasterKey1, Party1Public, party2::SignMessage};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenParty1Message2 {
    pub ecdh_second_message: party_one::KeyGenSecondMsg,
    pub ek: EncryptionKey,
    pub c_key: BigInt,
    pub correct_key_proof: NiCorrectKeyProof,
    pub pdl_statement: PDLwSlackStatement,
    pub pdl_proof: PDLwSlackProof,
    pub composite_dlog_proof: CompositeDLogProof,
}

impl MasterKey1 {
    pub fn set_master_key(
        chain_code: &BigInt,
        party_one_private: party_one::Party1Private,
        party_one_public_ec_key: &Point<Secp256k1>,
        party2_first_message_public_share: &Point<Secp256k1>,
        paillier_key_pair: party_one::PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: party_one::compute_pubkey(&party_one_private, party2_first_message_public_share),
            p1: party_one_public_ec_key.clone(),
            p2: party2_first_message_public_share.clone(),
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share.clone(),
        };

        MasterKey1 {
            public: party1_public,
            private: party_one_private,
            chain_code: chain_code.clone(),
        }
    }

    pub fn key_gen_first_message() -> (
        party_one::KeyGenFirstMsg,
        party_one::CommWitness,
        party_one::EcKeyPair,
    ) {
        party_one::KeyGenFirstMsg::create_commitments()
    }
    
    pub fn key_gen_second_message(
        comm_witness: party_one::CommWitness,
        ec_key_pair_party1: &party_one::EcKeyPair,
        proof: &DLogProof<Secp256k1, Sha256>,
    ) -> (
        KeyGenParty1Message2,
        party_one::PaillierKeyPair,
        party_one::Party1Private,
    ) {
        let key_gen_second_message =
            party_one::KeyGenSecondMsg::verify_and_decommit(comm_witness, proof).expect("");

        let paillier_key_pair =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

        // party one set her private key:
        let party_one_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

        let (pdl_statement, pdl_proof, composite_dlog_proof) =
            party_one::PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);

        let correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);

        (
            KeyGenParty1Message2 {
                ecdh_second_message: key_gen_second_message,
                ek: paillier_key_pair.ek.clone(),
                c_key: paillier_key_pair.encrypted_share.clone(),
                correct_key_proof,
                pdl_statement,
                pdl_proof,
                composite_dlog_proof,
            },
            paillier_key_pair,
            party_one_private,
        )
    }

    pub fn sign_first_message() -> (party_one::EphKeyGenFirstMsg, party_one::EphEcKeyPair) {
        party_one::EphKeyGenFirstMsg::create()
    }

    pub fn sign_second_message(
        &self,
        party_two_sign_message: &SignMessage,
        eph_key_gen_first_message_party_two: &party_two::EphKeyGenFirstMsg,
        eph_ec_key_pair_party1: &party_one::EphEcKeyPair,
        message: &BigInt,
    ) -> Result<party_one::SignatureRecid, Errors> {
        let verify_party_two_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &eph_key_gen_first_message_party_two,
                &party_two_sign_message.second_message,
            )
            .is_ok();

        let signature_with_recid = party_one::Signature::compute_with_recid(
            &self.private,
            &party_two_sign_message.partial_sig.c3,
            &eph_ec_key_pair_party1,
            &party_two_sign_message
                .second_message
                .comm_witness
                .public_share,
        );

        // Creating a standard signature for the verification, currently discarding recid
        // TODO: Investigate what verification could be done with recid
        let signature = party_one::Signature {
            r: signature_with_recid.r.clone(),
            s: signature_with_recid.s.clone(),
        };

        let verify = party_one::verify(&signature, &self.public.q, message).is_ok();
        if verify {
            if verify_party_two_second_message {
                Ok(signature_with_recid)
            } else {
                Err(Errors::SignError)
            }
        } else {
            Err(Errors::SignError)
        }
    }
}