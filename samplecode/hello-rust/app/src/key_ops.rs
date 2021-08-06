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

fn key_gen(enclave: EnclaveId,){

    let params: Parameters = Parameters{
        threshold: 1,   //t
        share_count: 3, //n
    };

    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    let delay = time::Duration::from_millis(600);

    let input_stage1 = KeyGenStage1Input {
        index: (party_num_int - 1) as usize,
    };

    let res_stage1: KeyGenStage1Result = enclave.keygen_stage1_exec(input_stage1);

    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
        uuid.clone()
    ).is_ok());

    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round1",
        uuid.clone(),
    );
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, res_stage1.bc_com1_l);
    assert!(broadcast(
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();
    decom1_vec.insert(party_num_int as usize - 1, res_stage1.decom1_l);
    let input_stage2 = KeyGenStage2Input {
        index: (party_num_int - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };

    let res_stage2: KeyGenStage2Result = enclave.keygen_stage2_exec(input_stage2);

    let mut point_vec: Vec<GE> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=params.share_count {
        point_vec.push(decom1_vec[(i - 1) as usize].y_i);
        if i != party_num_int {
            let key_bn: BigInt = (decom1_vec[(i - 1) as usize].y_i.clone()
                * res_stage1.party_keys_l.u_i)
                .x_coor()
                .unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let mut j = 0;
    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&res_stage2.secret_shares_s[k].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            // This client does not implement the identifiable abort protocol.
            // If it were these secret shares would need to be broadcasted to indetify the
            // malicious party.
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
                .is_ok());
            j += 1;
        }
    }
    // get shares from other parties.
    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round3",
        uuid.clone(),
    );
    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        uuid.clone()
    )
        .is_ok());
    //get vss_scheme for others.
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round4",
        uuid.clone(),
    );

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            vss_scheme_vec.push(res_stage2.vss_scheme_s.clone());
        } else {
            let vss_scheme_j: VerifiableSS<GE> = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }
    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l.clone(),
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        secret_shares_vec_s: party_shares,
        y_vec_s: point_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        params_s: params.clone(),
    };
    let res_stage3: KeyGenStage3Result = enclave.keygen_stage3_exec(input_stage3);
    // round 5: send dlog proof
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        params.share_count,
        delay,
        "round5",
        uuid.clone(),
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            dlog_proof_vec.push(res_stage3.dlog_proof_s.clone());
        } else {
            let dlog_proof_j: DLogProof<GE> = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec.clone(),
        y_vec_s: point_vec.clone(),
    };
    let _ = enclave.keygen_stage4_exec(input_stage4);

    //save key to file:
    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let h1_h2_N_tilde_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();
    let party_key_pair = PartyKeyPair {
        party_keys_s: res_stage1.party_keys_l.clone(),
        shared_keys: res_stage3.shared_keys_s.clone(),
        party_num_int_s: party_num_int,
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
        h1_h2_N_tilde_vec_s: h1_h2_N_tilde_vec,
    };
    fs::write(
        &env::args().nth(2).unwrap(),
        serde_json::to_string(&party_key_pair).unwrap(),
    )
        .expect("Unable to save !");

}

pub struct EnclaveId{
    enclave_id: sgx_enclave_id_t,
}

impl EnclaveId {
    pub fn new(enclave_id: sgx_enclave_id_t) -> EnclaveId{
        EnclaveId{
            enclave_id: enclave_id,
        }
    }

    fn get_enclave_id(&self) -> sgx_enclave_id_t{
        self.enclave_id
    }

    pub fn keygen_stage1_exec(&self,input_struct:KeyGenStage1Input) -> KeyGenStage1Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::keygen_stage1(self.get_enclave_id(),
                                 &mut retval,
                                 input.as_ptr() as * const u8,
                                 input.len(),
                                 out.as_ptr()  as * mut u8,
                                 out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: KeyGenStage1Result = serde_json::from_str(&trim).unwrap();
        result_struct
    }

    pub fn keygen_stage2_exec(&self,input_struct:KeyGenStage2Input) -> KeyGenStage2Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::keygen_stage2(self.get_enclave_id(),
                                 &mut retval,
                                 input.as_ptr() as * const u8,
                                 input.len(),
                                 out.as_ptr()  as * mut u8,
                                 out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: KeyGenStage2Result = serde_json::from_str(&trim).unwrap();
        result_struct
    }

    pub fn keygen_stage3_exec(&self,input_struct:KeyGenStage2Input) -> KeyGenStage3Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::keygen_stage3(self.get_enclave_id(),
                                 &mut retval,
                                 input.as_ptr() as * const u8,
                                 input.len(),
                                 out.as_ptr()  as * mut u8,
                                 out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: KeyGenStage3Result = serde_json::from_str(&trim).unwrap();
        result_struct
    }

    pub fn keygen_stage4_exec(&self,input_struct:KeyGenStage4Input) {

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::keygen_stage4(self.get_enclave_id(),
                                 &mut retval,
                                 input.as_ptr() as * const u8,
                                 input.len(),
                                 out.as_ptr()  as * mut u8,
                                 out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
//        let result_struct: KeyGenStage4Result = serde_json::from_str(&trim).unwrap();
//        result_struct
    }

    pub fn sign_stage1_exec(&self,input_struct:SignStage1Input) -> SignStage1Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::sign_stage1(self.get_enclave_id(),
                                 &mut retval,
                                 input.as_ptr() as * const u8,
                                 input.len(),
                                 out.as_ptr()  as * mut u8,
                                 out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: SignStage1Result = serde_json::from_str(&trim).unwrap();
        result_struct
    }

    pub fn sign_stage2_exec(&self,input_struct:SignStage2Input) -> SignStage2Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::sign_stage2(self.get_enclave_id(),
                               &mut retval,
                               input.as_ptr() as * const u8,
                               input.len(),
                               out.as_ptr()  as * mut u8,
                               out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: SignStage2Result = serde_json::from_str(&trim).unwrap();
        result_struct
    }

    pub fn sign_stage3_exec(&self,input_struct:SignStage3Input) -> SignStage3Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::sign_stage3(self.get_enclave_id(),
                               &mut retval,
                               input.as_ptr() as * const u8,
                               input.len(),
                               out.as_ptr()  as * mut u8,
                               out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: SignStage3Result = serde_json::from_str(&trim).unwrap();
        result_struct
    }

    pub fn sign_stage4_exec(&self,input_struct:SignStage4Input) -> SignStage4Result {

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::sign_stage4(self.get_enclave_id(),
                               &mut retval,
                               input.as_ptr() as * const u8,
                               input.len(),
                               out.as_ptr()  as * mut u8,
                               out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: SignStage4Result = serde_json::from_str(&trim).unwrap();
        result_struct
    }

    pub fn sign_stage5_exec(&self,input_struct:SignStage5Input) -> SignStage5Result{

        let input:String = serde_json::to_string(&input_struct).unwrap();

        let mut retval = sgx_status_t::SGX_SUCCESS;

        let mut out = vec![0; 40960];
        let result = unsafe {
            super::sign_stage5(self.get_enclave_id(),
                               &mut retval,
                               input.as_ptr() as * const u8,
                               input.len(),
                               out.as_ptr()  as * mut u8,
                               out.len(),
            )
        };
        let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
        let trim = str_out.replace("\u{0}","");
        let result_struct: SignStage5Result = serde_json::from_str(&trim).unwrap();
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