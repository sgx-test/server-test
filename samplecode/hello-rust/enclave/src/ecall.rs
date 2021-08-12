use super::*;

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
pub extern "C" fn keygen_stage1(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: KeyGenStage1Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage1 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage1(&input_struct);
    let output_result = serde_json::to_string(&output_struct).unwrap();
    let ttt: KeyGenStage1Result = serde_json::from_str(&output_result).unwrap();
    write_output(out, outlen, output_result);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn keygen_stage2(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: KeyGenStage2Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage2 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage2(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn keygen_stage3(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: KeyGenStage3Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage3 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage3(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn keygen_stage4(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: KeyGenStage4Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] keygen_stage4 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::keygen_stage4(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn sign_stage1(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: SignStage1Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage1 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage1(&input_struct);

    let output_result = serde_json::to_string(&output_struct).unwrap();
    write_output(out, outlen, output_result);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn sign_stage2(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: SignStage2Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage2 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage2(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn sign_stage3(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: SignStage3Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage3 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage3(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn sign_stage4(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: SignStage4Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage1 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage4(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn sign_stage5(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: SignStage5Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage5 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage5(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn sign_stage6(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: SignStage6Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage5 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage6(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}

#[no_mangle]
pub extern "C" fn sign_stage7(input: *const u8, inlen: usize, out: *mut u8, outlen: usize) -> sgx_status_t {
    let input = read_input(input, inlen);
    let input_struct: SignStage7Input = serde_json::from_str(&input).unwrap();
    //println!("[sgx] sign_stage5 serde result [{:?}]",input_struct);

    let output_struct = orchestrate::sign_stage7(&input_struct);

    if output_struct.is_err() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    } else {
        let output_result = serde_json::to_string(&output_struct.unwrap()).unwrap();
        write_output(out, outlen, output_result);

        return sgx_status_t::SGX_SUCCESS
    }
}
