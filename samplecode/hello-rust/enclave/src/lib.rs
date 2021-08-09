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

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;

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

extern crate paillier;
use paillier::*;

extern crate zk_paillier;
use zk_paillier::zkproofs::DLogStatement;

extern crate serde_json;

pub fn read_input(input: *const u8, input_len: usize) -> String{
    let str_slice = unsafe { slice::from_raw_parts(input, input_len) };
    let str = std::str::from_utf8(str_slice).unwrap();
    String::from(str)
}

pub fn write_output(out: *mut u8, outlen: usize, data:String){
    println!("[sgx] keygen_stage1 write_output len ,{:?}",data.as_bytes().len());
    let raw_buf = unsafe { slice::from_raw_parts_mut(out as * mut u8, data.as_bytes().len() as usize) };
    raw_buf.copy_from_slice(&data.as_bytes());
}

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

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
fn keygen_stage1(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: KeyGenStage1Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage1 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage1(&input_struct);
    let output_result = serde_json::to_string(&output_struct).unwrap();
    let ttt: KeyGenStage1Result = serde_json::from_str(&output_result).unwrap();
    write_output(out,outlen,output_result);
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
fn keygen_stage2(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: KeyGenStage2Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage2 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage2(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }

}

#[no_mangle]
fn keygen_stage3(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: KeyGenStage3Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage3 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage3(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
fn keygen_stage4(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: KeyGenStage4Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage4 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage4(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
fn sign_stage1(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: SignStage1Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage1 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage1(&input_struct);

    let output_result = serde_json::to_string(&output_struct).unwrap();
    write_output(out,outlen,output_result);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
fn sign_stage2(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: SignStage2Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage2 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage2(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
fn sign_stage3(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: SignStage3Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage3 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage3(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
fn sign_stage4(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: SignStage4Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage1 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage4(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
fn sign_stage5(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: SignStage5Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage5 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage5(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
fn sign_stage6(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: SignStage6Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage5 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage6(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
fn sign_stage7(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{

    let input = read_input(input,inlen);
    let input_struct: SignStage7Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage5 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage7(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out,outlen,output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;

use sgx_types::{ sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use sgx_rand::{Rng, StdRng};


use multi_party_ecdsa::PartyKeyPair;

#[no_mangle]
pub extern "C" fn create_sealeddata_for_serializable(data:PartyKeyPair,sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

//    let mut data = PartyKeyPair::default();
//    data.key = 0x1234;
//
//    let mut rand = match StdRng::new() {
//        Ok(rng) => rng,
//        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
//    };
//    rand.fill_bytes(&mut data.rand);
//
//    data.vec.extend(data.rand.iter());

    let encoded_vec = serde_cbor::to_vec(&data).unwrap();
    let encoded_slice = encoded_vec.as_slice();
    println!("Length of encoded slice: {}", encoded_slice.len());
    println!("Encoded slice: {:?}", encoded_slice);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return ret; },
    };

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealeddata_for_serializable(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let opt = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

    let encoded_slice = unsealed_data.get_decrypt_txt();
    println!("Length of encoded slice: {}", encoded_slice.len());
    println!("Encoded slice: {:?}", encoded_slice);
    let data: PartyKeyPair = serde_cbor::from_slice(encoded_slice).unwrap();

    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<[T]>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

//#[no_mangle]
//fn keygen_stage2(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t{
//
//    let str_slice = unsafe { slice::from_raw_parts(input, inlen) };
//
//    let str_in = std::str::from_utf8(str_slice).unwrap();
//
//    //let input: KeyGenStage1Input = serde_json::from_str(&str_in).unwrap();
//    //println!("keygen_stage1 in sgx {:?}",input);
//
//    let raw_buf = unsafe { slice::from_raw_parts_mut(out as * mut u8, str_slice.len() as usize) };
//    raw_buf.copy_from_slice(str_slice);
//
//    sgx_status_t::SGX_SUCCESS
//}
