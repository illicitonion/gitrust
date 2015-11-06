mod git;

extern crate getopts;
extern crate hyper;
extern crate rustc_serialize;
extern crate tempdir;

use getopts::Options;
use hyper::net::Openssl;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use rustc_serialize::json::{self, Json};
use std::env;
use std::error::Error;
use std::io::Read;
use std::string::String;

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
    if path.starts_with("/squashmerge") {
        match req.method {
            hyper::Post => { handle_squash_request(req, res) ; return },
            _ => { let _ = *res.status_mut() = StatusCode::MethodNotAllowed ; return },
        }
    }
    *res.status_mut() = StatusCode::NotFound;
}

fn handle_squash_request(mut req: Request, mut res: Response) {
    let mut body = String::new();

    if !req.read_to_string(&mut body).is_ok() {
        let _ = *res.status_mut() = StatusCode::BadRequest;
        return
    }

    let (base_repo, base_branch, head_repo, head_branch, commit_message, username, password) = match parse_body( &body) {
        Ok((base_repo, base_branch, head_repo, head_branch, commit_message, username, password)) => (base_repo, base_branch, head_repo, head_branch, commit_message, username, password),
        Err(err) => { 
            let message = json::encode(&err.description()).unwrap_or("\"error\"".to_owned());
            let _ = res.send(format!("{{\"message\": {}}}", message).as_bytes());
            return;
        },
    };

    let merged = git::squash_merge(
        &base_repo,
        &base_branch,
        &head_repo,
        &head_branch,
        &commit_message,
        &username,
        &password
    );

    let (code, resp) = match merged {
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

fn parse_body(body_string: &String) -> Result<(String, String, String, String, String, String, String), Box<Error + Send + Sync>> {
    let body = try!(Json::from_str(body_string));
    let base_repo = match get_string(&body, "base_repo") {
        Some(v) => v,
        None => return Err(From::from("missing base_repo")),
    };
    let base_branch = match get_string(&body, "base_branch") {
        Some(v) => v,
        None => return Err(From::from("missing base_branch")),
    };
    let head_repo = match get_string(&body, "head_repo") {
        Some(v) => v,
        None => return Err(From::from("missing head_repo")),
    };
    let head_branch = match get_string(&body, "head_branch") {
        Some(v) => v,
        None => return Err(From::from("missing head_branch")),
    };
    let commit_message = match get_string(&body, "commit_message") {
        Some(v) => v,
        None => return Err(From::from("missing commit_message")),
    };
    let username = match get_string(&body, "username") {
        Some(v) => v,
        None => return Err(From::from("missing username")),
    };
    let password = match get_string(&body, "password") {
        Some(v) => v,
        None => return Err(From::from("missing password")),
    };
    return Ok((base_repo, base_branch, head_repo, head_branch, commit_message, username, password));
}

fn get_string(obj: &Json, key: &str) -> Option<String> {
    let s = match obj.find(key) {
        Some(v) => v,
        None => return None,
    };
    return s.as_string().map_or(None, |s| Some(s.to_owned()))
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
