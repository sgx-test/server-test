// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..
#![feature(proc_macro_hygiene, decl_macro)]

extern crate sgx_types;
extern crate sgx_urts;
use sgx_types::*;
use sgx_urts::SgxEnclave;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern crate multi_party_ecdsa;
extern crate crypto;
extern crate reqwest;
extern crate serde;

mod key_ops;
use key_ops::{EnclaveId,};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::{self,*};
mod server;

mod common;
use common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params,
    PartySignup, AEAD, AES_KEY_BYTES_LEN,
};

extern {
    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
    fn keygen_stage1(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     input: *const u8, inlen: usize,
                     out: *mut u8, outlen: usize) -> sgx_status_t;
    fn keygen_stage2(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     input: *const u8, inlen: usize,
                     out: *mut u8, outlen: usize) -> sgx_status_t;
    fn keygen_stage3(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     input: *const u8, inlen: usize,
                     out: *mut u8, outlen: usize) -> sgx_status_t;
    fn keygen_stage4(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     input: *const u8, inlen: usize,
                     out: *mut u8, outlen: usize) -> sgx_status_t;
    fn sign_stage1(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     input: *const u8, inlen: usize,
                     out: *mut u8, outlen: usize) -> sgx_status_t;
    fn sign_stage2(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                   input: *const u8, inlen: usize,
                   out: *mut u8, outlen: usize) -> sgx_status_t;
    fn sign_stage3(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                   input: *const u8, inlen: usize,
                   out: *mut u8, outlen: usize) -> sgx_status_t;
    fn sign_stage4(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                   input: *const u8, inlen: usize,
                   out: *mut u8, outlen: usize) -> sgx_status_t;
    fn sign_stage5(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                   input: *const u8, inlen: usize,
                   out: *mut u8, outlen: usize) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    let input_string = String::from("This is a normal world string passed into Enclave!\n");
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        say_something(enclave.geteid(),
                      &mut retval,
                      input_string.as_ptr() as * const u8,
                      input_string.len())
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    println!("[+] say_something success...");

//    let input = String::from("{\"index\":5,\"test_data\":{\"data1\":[1,[2102096]],\"data2\":4}}");
//    let mut out = vec![0; 1024];
//    let result = unsafe {
//        keygen_stage1(enclave.geteid(),
//                      &mut retval,
//                      input.as_ptr() as * const u8,
//                      input.len(),
//                      out.as_ptr()  as * mut u8,
//                      out.len(),
//        )
//    };
//    let str_out = std::str::from_utf8(&out).unwrap();
    println!("[+] KeyGenStage1Input input...");
    let input_stage1 = KeyGenStage1Input {
        index: (2 - 1) as usize,
    };
    let enc = EnclaveId::new(enclave.geteid());
    let res_stage1: KeyGenStage1Result = enc.keygen_stage1_exec(input_stage1);
    println!("[+] KeyGenStage1Input out = {:?}",res_stage1);

    enclave.destroy();
}
