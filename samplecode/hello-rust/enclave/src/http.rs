use std::prelude::v1::*;
use http_req::request::*;
use http_req::response::*;
use http_req::tls;
use http_req::uri::Uri;
use http_req::{error::Error, response::StatusCode};
use std::net::TcpStream;
use http_req::request;
use std::*;

pub fn http() {
    let mut writer = Vec::new(); //container for body of a response
    let res = request::get("https://doc.rust-lang.org/", &mut writer).unwrap();

    println!("Status: {} {}", res.status_code(), res.reason());
}

pub fn get(addr:String, body:Vec<u8>) -> Option<String> {

    let mut writer = Vec::new();
    let uri = addr.parse().unwrap();

    let retry_delay = time::Duration::from_millis(250);
    for _i in 1..3 {
        let res = Request::new(&uri)
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .body(&body)
            .send(&mut writer);

        if let Ok(mut resp) = res {
            let body = str::from_utf8(&writer).unwrap();
            return Some(body.to_string());
        }

        thread::sleep(retry_delay);
    }
    None
}