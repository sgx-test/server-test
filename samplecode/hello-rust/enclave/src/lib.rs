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

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
extern crate serde_cbor;
extern crate sgx_tseal;
extern crate sgx_types;
extern crate serde;
extern crate hex;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use std::string::ToString;

extern crate multi_party_ecdsa;

use multi_party_ecdsa::curv::arithmetic::traits::Converter;
use multi_party_ecdsa::curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use multi_party_ecdsa::curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use multi_party_ecdsa::curv::elliptic::curves::secp256_k1::{FE, GE};
use multi_party_ecdsa::curv::elliptic::curves::traits::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::{self,*};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters, SharedKeys,
};
use serde::{Deserialize, Serialize};

extern crate paillier;
use paillier::*;

extern crate zk_paillier;
use zk_paillier::zkproofs::DLogStatement;

extern crate serde_json;

extern crate http_req;

pub mod key_gen;
use key_gen::*;

pub mod key_sign;
use key_gen::*;

pub mod http;
use http::*;

pub mod common;
use common::*;

pub mod ecall;
use ecall::*;

pub mod seal;
use seal::*;

#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a in-Enclave ";
    // An array
    let word:[u8;4] = [82, 117, 115, 116];
    // An vector
    let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8")
        .as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    println!("ocall_dada 1 ");
    let ocall_dada = Stage {
        round: "round1".to_string(),
        party_num_int: 1u16,
        output: "output".to_string(),
        uuid: "adf_dsaf_11".to_string(),
    };
    let ocall_dada:String = serde_json::to_string(&ocall_dada).unwrap();
    println!("ocall_dada in ocall_dada{:?}",ocall_dada);
    let mut out = vec![0; 4096];
    let mut ret_val= sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ocall_broadcast(
            &mut ret_val as *mut sgx_status_t,
            ocall_dada.as_ptr() as * const u8,
            ocall_dada.len(),
            out.as_ptr()  as * mut u8,
            out.len(),
        )
    };
    println!("ocall_dada 2 result{:?}",result);
    let mut str_out = std::str::from_utf8(&out).unwrap().to_string();
    let trim = str_out.replace("\u{0}","");
    println!("ocall_dada 2 output{:?}",trim);

    sgx_status_t::SGX_SUCCESS
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stage {
    pub round: String,
    pub party_num_int: u16,
    pub output: String,
    pub uuid: String,
}

extern "C" {
    fn ocall_broadcast(ret_val: *mut sgx_status_t, input: *const u8, inlen: usize,
                   out: *mut u8, outlen: usize) -> sgx_status_t;
}

