use std::prelude::v1::*;
use http_req::request::*;
use http_req::response::*;
use http_req::tls;
use http_req::uri::Uri;
use http_req::{error::Error, response::StatusCode};
use std::net::TcpStream;
use http_req::request;
use std::*;
use serde::{Deserialize, Serialize};

pub fn http() {
    let mut writer = Vec::new(); //container for body of a response
    let res = request::get("https://doc.rust-lang.org/", &mut writer).unwrap();

    println!("Status: {} {}", res.status_code(), res.reason());
}

pub fn postb<T>(addr:String, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize
{
    let body_string = serde_json::to_string(&body).unwrap();
    let mut writer = Vec::new();

    let uri = format!("{}/{}", addr, path);
    let uri = uri.parse().unwrap();

    let retry_delay = time::Duration::from_millis(500);
    for _i in 1..4 {
        let res = Request::new(&uri)
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .header("Content-Length", &body_string.as_bytes().len())
            .body(&body_string.as_bytes())
            .send(&mut writer);

        if let Ok(mut resp) = res {
            let body = str::from_utf8(&writer).unwrap();
            return Some(body.to_string());
        }

        thread::sleep(retry_delay);
    }
    None
}