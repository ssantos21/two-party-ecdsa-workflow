pub mod ecdsa;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    KeyGenError,
    SignError,
}

#[cfg(test)]
mod tests {
    use std::cmp;

    use curv::{BigInt, elliptic::curves::{Scalar, Secp256k1}, arithmetic::Modulo};
    use crate::ecdsa::two_party::{MasterKey1, MasterKey2};
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
    use zk_paillier::zkproofs::SALT_STRING;
    
    #[test]
    fn test_key_gen_and_signature() {
        let (party_one_master_key, party_two_master_key) = test_key_gen();

        let message = BigInt::from(1234);

        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
                MasterKey2::sign_first_message();

        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();

        let sign_party_two_second_message = party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message,
            &message,
        );

        let sign_party_one_second_message = party_one_master_key.sign_second_message(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
            &message,
        ).expect("bad signature");

        let signature = party_one::Signature {
            r: sign_party_one_second_message.r,
            s: sign_party_one_second_message.s,
        };

        party_one::verify(&signature, &party_one_master_key.public.q, &message).expect("Invalid signature");
    }

    #[test]
    fn test_key_gen_and_blinded_signature() {
        let (party_one_master_key, party_two_master_key) = test_key_gen();

        let message = BigInt::from(1234);

        let (sign_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
                MasterKey2::sign_first_message();

        let (sign_party_one_first_message, eph_ec_key_pair_party1) =
            MasterKey1::sign_first_message();

        let blinding_factor = Scalar::<Secp256k1>::random();
        let inv_blinding_factor = blinding_factor.invert().unwrap();

        let sign_party_two_second_message = party_two_master_key.sign_second_message_with_blinding_factor(
            &eph_ec_key_pair_party2,
            eph_comm_witness,
            &sign_party_one_first_message,
            &message,
            &blinding_factor.to_bigint(),
        );

        let blinded_signature = party_one_master_key.sign_second_message_with_blinding_factor(
            &sign_party_two_second_message,
            &sign_party_two_first_message,
            &eph_ec_key_pair_party1,
        );

        let q = Scalar::<Secp256k1>::group_order();

        let unblinded_signature_s1 = BigInt::mod_mul(&blinded_signature.s, &inv_blinding_factor.to_bigint(), &q);

        let unblinded_message_s = cmp::min(
            unblinded_signature_s1.clone(),
            q - unblinded_signature_s1,
        );

        let signature = party_one::Signature {
            r: sign_party_two_second_message.partial_sig.r,
            s: unblinded_message_s,
        };

        party_one::verify(&signature, &party_one_master_key.public.q, &message).expect("Invalid signature");
    }

    pub fn test_key_gen() -> (MasterKey1, MasterKey2) {

        // key gen
        let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
            MasterKey1::key_gen_first_message();
    
        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();
    
        let (kg_party_one_second_message, party_one_paillier_key_pair, party_one_private) =
            MasterKey1::key_gen_second_message(
                kg_comm_witness.clone(),
                &kg_ec_key_pair_party1,
                &kg_party_two_first_message.d_log_proof,
            );
    
        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
            SALT_STRING
        );
    
        assert!(key_gen_second_message.is_ok());
        let party_two_paillier = key_gen_second_message.unwrap().1;
    
        // set master keys:
        let party_one_master_key = MasterKey1::set_master_key(
            &BigInt::from(0),
            party_one_private,
            &kg_comm_witness.public_share,
            &kg_party_two_first_message.public_share,
            party_one_paillier_key_pair,
        );
    
        let party_two_master_key = MasterKey2::set_master_key(
            &BigInt::from(0),
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier,
        );
    
        (party_one_master_key, party_two_master_key)
    }
}
