#[macro_use]
mod macros;

mod git;

extern crate getopts;
extern crate hyper;
extern crate oauth2;
extern crate queryst;
extern crate rustc_serialize;
extern crate tempdir;
extern crate unicase;
extern crate url;
extern crate uuid;

use getopts::Options;
use hyper::header;
use hyper::net::Openssl;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use oauth2::Config;
use rustc_serialize::Encodable;
use rustc_serialize::json::{self, Json};
use queryst::parse;
use std::env;
use std::error::Error;
use std::io::Read;
use std::string::String;
use unicase::UniCase;
use url::parse_path;
use self::uuid::Uuid;

fn main() {
    let (listen_address, ssl, oauth_config, oauth_redirect_path) = parse_flags();

    let handler = Handler{ oauth_config: oauth_config, oauth_redirect_path: oauth_redirect_path, };

    println!("Listening on {}", listen_address);
    if ssl.is_some() {
        Server::https(&listen_address[..], ssl.unwrap()).unwrap().handle(handler).unwrap();
    } else {
        Server::http(&listen_address[..]).unwrap().handle(handler).unwrap();
    }
}

fn parse_flags() -> (String, Option<Openssl>, oauth2::Config, String) {
    let mut opts = Options::new();

    opts.optopt("p", "port", "Port on which to listen", "3000");
    opts.optopt("i", "interface", "Interface on which to listen", "0.0.0.0");

    opts.optflag("s", "ssl", "Whether to listen for HTTPS or just HTTP");
    opts.optopt("c", "certfile", "SSL certificate file", "/path/to/foo.crt");
    opts.optopt("k", "keyfile", "SSL key file", "/path/to/foo.key");

    opts.optopt("h", "host_and_port", "Hostname and port", "127.0.0.1:443");
    opts.optopt("", "oauth_client_id", "Github oauth client ID", "clientid");
    opts.optopt("", "oauth_client_secret", "Github oauth client secret", "clientsecret");
    opts.optopt("", "oauth_redirect_path", "Github oauth redirect URL", "/oauth/redirect");

    let args: Vec<String> = env::args().collect();
    let matches = opts.parse(&args[1..]).unwrap();
    let interface = matches.opt_str("i").unwrap_or("0.0.0.0".to_owned());
    let port = matches.opt_str("p").unwrap_or("3000".to_owned());

    let ssl = match matches.opt_present("s") {
        true => Some(Openssl::with_cert_and_key(matches.opt_str("c").unwrap(), matches.opt_str("k").unwrap()).unwrap()),
        false => None,
    };

    let mut oauth_config = oauth2::Config::new(
        &matches.opt_str("oauth_client_id").unwrap(),
        &matches.opt_str("oauth_client_secret").unwrap(),
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token"
    );
    oauth_config.scopes.push("repo".to_owned());
    let oauth_redirect_path = matches.opt_str("oauth_redirect_path").unwrap();
    oauth_config.redirect_url = format!("https://{}{}", matches.opt_str("host_and_port").unwrap(), oauth_redirect_path);

    let host_and_port = format!("{}:{}", interface, port);
    return (host_and_port, ssl, oauth_config, oauth_redirect_path);
}

struct Handler {
    oauth_config: oauth2::Config,
    oauth_redirect_path: String,
}

impl hyper::server::Handler for Handler {
    fn handle(&self, req: Request, mut res: Response) {
        let (path, qs) = match req.uri {
            AbsolutePath(ref p) => match parse_path(p) {
                Ok((path, qs, _)) => (format!("/{}", path.join("/")), qs),
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
            "/oauth/authorize" => match req.method {
                hyper::Get => self.handle_oauth_authorize_request(res),
                _ => self.not_allowed(res),
            },
            _ => {
                if path == &self.oauth_redirect_path[..] {
                    match req.method {
                        hyper::Get => match qs {
                            Some(q) => self.handle_oauth_exchange_request(&q, res),
                            None => self.bad_request(res),
                        },
                        _ => self.not_allowed(res),
                    }
                } else {
                    self.not_found(res);
                }
            },
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

    fn handle_oauth_authorize_request(&self, mut res: Response) {
        let _ = *res.status_mut() = StatusCode::Found;
        res.headers_mut().set(header::Location(self.oauth_config.authorize_url(Uuid::new_v4().to_hyphenated_string()).to_string()));
    }

    fn handle_oauth_exchange_request(&self, qs: &str, res: Response) {
        let obj = match parse(qs) {
            Ok(q) => q,
            Err(err) => { self.error(res, &format!("Error parsing querystring: {}", err.message)); return },
        };
        let code = match obj.find("code") {
            Some(c) => match c.as_string() {
                Some(c) => c,
                None => { self.error(res, "code not a string"); return },
            },
            None => { self.error(res, "No code present"); return },
        };
        let token = self.oauth_config.exchange(code.to_owned());
        match token {
            Ok(tok) => self.send_json(res, &TokenResponse { access_token: &tok.access_token }),
            Err(tok) => self.error(res, &format!("Error exchanging token: {}", tok)),
        };
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

    fn bad_request(&self, mut res: Response) {
        let _ = *res.status_mut() = StatusCode::BadRequest;
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

#[derive(RustcEncodable)]
struct TokenResponse<'a> {
    access_token: &'a str,
}
