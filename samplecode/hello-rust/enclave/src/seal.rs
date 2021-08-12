use super::*;
use sgx_types::{ sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};

use multi_party_ecdsa::PartyKeyPair;

#[no_mangle]
pub extern "C" fn create_sealeddata_for_serializable(data:PartyKeyPair,sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

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