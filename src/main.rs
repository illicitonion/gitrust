#[macro_use]
mod macros;

mod git;

extern crate getopts;
extern crate hyper;
extern crate rustc_serialize;
extern crate tempdir;
extern crate unicase;
extern crate url;

use getopts::Options;
use hyper::header;
use hyper::net::Openssl;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use rustc_serialize::Encodable;
use rustc_serialize::json::{self, Json};
use std::env;
use std::error::Error;
use std::io::Read;
use std::string::String;
use unicase::UniCase;
use url::parse_path;

fn main() {
    let (listen_address, ssl) = parse_flags();

    let handler = Handler;

    println!("Listening on {}", listen_address);
    if ssl.is_some() {
        Server::https(&listen_address[..], ssl.unwrap()).unwrap().handle(handler).unwrap();
    } else {
        Server::http(&listen_address[..]).unwrap().handle(handler).unwrap();
    }
}

fn parse_flags() -> (String, Option<Openssl>) {
    let mut opts = Options::new();

    opts.optopt("p", "port", "Port on which to listen", "3000");
    opts.optopt("i", "interface", "Interface on which to listen", "0.0.0.0");

    opts.optflag("s", "ssl", "Whether to listen for HTTPS or just HTTP");
    opts.optopt("c", "certfile", "SSL certificate file", "/path/to/foo.crt");
    opts.optopt("k", "keyfile", "SSL key file", "/path/to/foo.key");

    let args: Vec<String> = env::args().collect();
    let matches = opts.parse(&args[1..]).unwrap();
    let interface = matches.opt_str("i").unwrap_or("0.0.0.0".to_owned());
    let port = matches.opt_str("p").unwrap_or("3000".to_owned());

    let ssl = match matches.opt_present("s") {
        true => Some(Openssl::with_cert_and_key(matches.opt_str("c").unwrap(), matches.opt_str("k").unwrap()).unwrap()),
        false => None,
    };

    let host_and_port = format!("{}:{}", interface, port);
    return (host_and_port, ssl);
}

struct Handler;

impl hyper::server::Handler for Handler {
    fn handle(&self, req: Request, mut res: Response) {
        let path = match req.uri {
            AbsolutePath(ref p) => match parse_path(p) {
                Ok((path, _, _)) => format!("/{}", path.join("/")),
                Err(err) => { self.error(res, err.description()); return },
            },
            _ => { self.not_found(res); return },
        };

        res.headers_mut().set(header::AccessControlAllowOrigin::Any);
        res.headers_mut().set(header::AccessControlAllowHeaders(vec![UniCase("content-type".to_owned())]));

        if req.method == hyper::method::Method::Options {
            return
        }

        match &path[..] {
            "/squashmerge" => match req.method {
                hyper::Post => { self.handle_request(req, res, Handler::handle_squash_request) },
                _ => self.not_allowed(res)
            },
            "/rewritehistory" => match req.method {
                hyper::Post => { self.handle_request(req, res, Handler::handle_rewrite_history_request) },
                _ => self.not_allowed(res),
            },
            _ => self.not_found(res),
        };
    }
}

impl Handler {
    fn handle_request<F>(&self, mut req: Request, res: Response, handler: F)
        where F : Fn(&str) -> Result<String, String> {

        let mut body_string = String::new();
        let err = req.read_to_string(&mut body_string);
        if err.is_err() {
            self.error(res, &err.err().unwrap().description());
            return;
        }

        match handler(&body_string) {
            Ok(sha) => self.send_json(res, &ShaResponse { sha: &sha, merged: true }),
            Err(err) => self.error(res, &err),
        };
    }

    fn handle_squash_request(body_string: &str) -> Result<String, String> {
        let body = try_or_string!(Json::from_str(body_string));

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

    fn handle_rewrite_history_request(body_string: &str) -> Result<String, String> {
        let body = try_or_string!(Json::from_str(body_string));

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

    fn send_json<T: Encodable>(&self, mut res: Response, obj: &T) {
        match json::encode(obj) {
            Ok(o) => { let _ = res.send(o.as_bytes()); },
            Err(_) => {
                let _ = *res.status_mut() = StatusCode::InternalServerError;
                let _ = res.send("{\"message\": \"error serializing response\"}".as_bytes());
            },
        };
    }

    fn error(&self, mut res: Response, description: &str) {
        let _ = *res.status_mut() = StatusCode::InternalServerError;
        self.send_json(res, &ErrorResponse { message: description });
    }

    fn not_allowed(&self, mut res: Response) {
        let _ = *res.status_mut() = StatusCode::MethodNotAllowed;
    }

    fn not_found(&self, mut res: Response) {
        let _ = *res.status_mut() = StatusCode::NotFound;
    }
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
