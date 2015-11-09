mod git;

extern crate getopts;
extern crate hyper;
extern crate rustc_serialize;
extern crate tempdir;
extern crate unicase;

use getopts::Options;
use hyper::header;
use hyper::net::Openssl;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use rustc_serialize::json::{self, Json};
use std::env;
use std::error::Error;
use std::io::Read;
use std::string::String;
use unicase::UniCase;

fn main() {
    let (listen_address, ssl) = get_listen_address();
    println!("Listening on {}", listen_address);
    if ssl.is_some() {
        Server::https(&listen_address[..], ssl.unwrap()).unwrap().handle(handle).unwrap();
    } else {
        Server::http(&listen_address[..]).unwrap().handle(handle).unwrap();
    }
}

fn get_listen_address() -> (String, Option<Openssl>) {
    let mut opts = Options::new();
    opts.optopt("p", "port", "Port on which to listen", "3000");
    opts.optopt("i", "interface", "Interface on which to listen", "0.0.0.0");
    opts.optflag("s", "ssl", "Whether to listen for HTTPS or just HTTP");
    opts.optopt("c", "certfile", "SSL certificate file", "/path/to/foo.crt");
    opts.optopt("k", "keyfile", "SSL key file", "/path/to/foo.key");
    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(err) => panic!(err),
    };
    let interface = matches.opt_str("i").unwrap_or("0.0.0.0".to_owned());
    let port = matches.opt_str("p").unwrap_or("3000".to_owned());

    let mut ssl = None;
    if matches.opt_present("s") {
        ssl = Some(Openssl::with_cert_and_key(matches.opt_str("c").unwrap(), matches.opt_str("k").unwrap()).unwrap());
    }

    return (format!("{}:{}", interface, port), ssl);
}

fn handle(req: Request, mut res: Response) {
    let path = match req.uri {
        AbsolutePath(ref p) => p.clone(),
        _ => { let _ = *res.status_mut() = StatusCode::NotFound ; return },
    };

    res.headers_mut().set(header::AccessControlAllowOrigin::Any);
    res.headers_mut().set(header::AccessControlAllowHeaders(vec![UniCase("content-type".to_owned())]));

    if req.method == hyper::method::Method::Options {
        return
    }

    match &path[..] {
        "/squashmerge" => {
            match req.method {
                hyper::Post => { handle_request(req, res, handle_squash_request) ; return },
                _ => { let _ = *res.status_mut() = StatusCode::MethodNotAllowed ; return },
            }
        },
        "/rewritehistory" => {
            match req.method {
                hyper::Post => { handle_request(req, res, handle_rewrite_history_request) ; return },
                _ => { let _ = *res.status_mut() = StatusCode::MethodNotAllowed ; return },
            }
        },
        _ => { let _ = *res.status_mut() = StatusCode::NotFound; }
    };
}

macro_rules! get_json_string {
    ( $obj:expr, $key:expr ) => {
        {
            let val = match $obj.find($key) {
                Some(v) => v,
                None => return Err(From::from(format!("missing {}", $key))),
            };
            let s = match val.as_string() {
                Some(v) => v,
                None => return Err(From::from(format!("not a string: {}", $key))),
            };
            s
        }
    }
}

fn handle_request<F>(mut req: Request, mut res: Response, handler: F)
    where F : Fn(&str) -> Result<String, Box<Error + Send + Sync>> {

    let mut body_string = String::new();
    if !req.read_to_string(&mut body_string).is_ok() {
        let _ = *res.status_mut() = StatusCode::InternalServerError;
        let _ = res.send("\"message\": \"error reading body\"}".as_bytes());
        return
    }

    let (code, resp) = match handler(&body_string) {
        Ok(sha) => json::encode(&ShaResponse { sha: &sha, merged: true }).ok().map_or(
            (StatusCode::InternalServerError, "{\"message\": \"error serializing response\"}".to_owned()),
            |r| (StatusCode::Ok, r)
        ),
        Err(err) => json::encode(&ErrorResponse { message: err.description() }).ok().map_or(
            (StatusCode::InternalServerError, "{\"message\": \"error serializing response\"}".to_owned()),
            |r| (StatusCode::InternalServerError, r)
        ),
    };

    let _ = *res.status_mut() = code;
    let _ = res.send(resp.as_bytes());
}

fn handle_squash_request(body_string: &str) -> Result<String, Box<Error + Send + Sync>> {
    let body = try!(Json::from_str(body_string));

    return git::squash_merge(
        get_json_string!(body, "base_repo"),
        get_json_string!(body, "base_branch"),
        get_json_string!(body, "head_repo"),
        get_json_string!(body, "head_branch"),
        get_json_string!(body, "commit_message"),
        get_json_string!(body, "username"),
        get_json_string!(body, "password"),
    );
}

fn handle_rewrite_history_request(body_string: &str) -> Result<String, Box<Error + Send + Sync>> {
    let body = try!(Json::from_str(body_string));

    return git::rewrite_history(
        get_json_string!(body, "repo"),
        get_json_string!(body, "branch"),
        get_json_string!(body, "baseline_repo"),
        get_json_string!(body, "baseline_branch"),
        get_json_string!(body, "commit_message"),
        get_json_string!(body, "username"),
        get_json_string!(body, "password")
    );
}

#[derive(RustcEncodable)]
struct ShaResponse<'a> {
    sha: &'a str,
    merged: bool,
}

#[derive(RustcEncodable)]
struct ErrorResponse<'a> {
    message: &'a str,
}
