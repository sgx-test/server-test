use std::thread::sleep;
use std::time::Duration;

use key_ops::{key_gen,EnclaveId};
//use multi_party_ecdsa::gg20;
//use gg20::gg20_keygen::ken_gen;
//use gg20::gg20_sign::key_sign;
//use gg20::sm_manager::start_sm_manager;

//use multi_party_ecdsa::gg20::filecoin;
//use filecoin::{filecoin_message,filecoin_message_signed,convert_signtature};

use super::*;

pub fn test_key_gen(en_id : sgx_enclave_id_t) {

    println!("===========start=========");
    for i in vec![1,2,3] {
        std::thread::spawn(move || {

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


            key_gen(EnclaveId::new(enclave.geteid()));


            enclave.destroy();
        });
    }

    println!("===========sleep=========");
    sleep(Duration::from_secs(10));

}