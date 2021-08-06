use std::{env, iter::repeat, thread, time, time::Duration};

use multi_party_ecdsa::curv::arithmetic::traits::Converter;
use multi_party_ecdsa::curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use multi_party_ecdsa::curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use multi_party_ecdsa::curv::elliptic::curves::secp256_k1::{FE, GE};
use multi_party_ecdsa::curv::elliptic::curves::traits::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::{self,*};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters, SharedKeys,
};

use multi_party_ecdsa::*;
use multi_party_ecdsa::zk_paillier::zkproofs::DLogStatement;
use multi_party_ecdsa::paillier::EncryptionKey;

extern crate serde_json;
use serde::{Deserialize, Serialize};

use super::common;
use common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params,
    PartySignup, AEAD, AES_KEY_BYTES_LEN,
};

use reqwest::Client;

use super::*;

fn key_gen(eid: sgx_enclave_id_t,){

    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    let delay = time::Duration::from_millis(25);

    let input_stage1 = KeyGenStage1Input {
        index: (party_num_int - 1) as usize,
    };



}

struct EnclaveId{
    enclave_id: sgx_enclave_id_t,
}

impl EnclaveId {
    pub fn new(enclave_id: sgx_enclave_id_t) -> EnclaveId{
        EnclaveId{
            enclave_id: enclave_id,
        }
    }

    pub fn get_enclave_id(&self) -> sgx_enclave_id_t{
        self.enclave_id
    }

    pub fn keygen_stage1_exec(&self,input_struct:KeyGenStage1Input) -> KeyGenStage1Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 1024];
        let result = unsafe {
            super::keygen_stage1(self.get_enclave_id(),
                          &mut retval,
                          input.as_ptr() as * const u8,
                          input.len(),
                          out.as_ptr()  as * mut u8,
                          out.len(),
            )
        };
        let str_out = std::str::from_utf8(&out).unwrap();
        let result_struct: KeyGenStage1Result = serde_json::from_str(&str_out).unwrap();
        result_struct
    }

}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS<GE>>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_N_tilde_vec_s: Vec<DLogStatement>,
}

pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-keygen".to_string();

    let res_body = postb(&client, "signupkeygen", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}