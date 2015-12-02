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
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::io::Read;
use std::string::String;
use std::sync::{Arc, Mutex};
use unicase::UniCase;
use url::{parse_path, Url};
use self::uuid::Uuid;

fn main() {
    let (listen_address, ssl, oauth_config, oauth_redirect_path, whitelisted_domains) = parse_flags();

    let handler = Handler{
        oauth_config: oauth_config,
        oauth_redirect_path: oauth_redirect_path,
        whitelisted_domains: whitelisted_domains,
        redirect_uris: Arc::new(Mutex::new(HashMap::new())),
    };

    println!("Listening on {}", listen_address);
    if ssl.is_some() {
        Server::https(&listen_address[..], ssl.unwrap()).unwrap().handle(handler).unwrap();
    } else {
        Server::http(&listen_address[..]).unwrap().handle(handler).unwrap();
    }
}

fn parse_flags() -> (String, Option<Openssl>, oauth2::Config, String, HashSet<String>) {
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

    opts.optopt("d", "whitelisted_domains", "Hostname and port of domains to which to allow redirection (comma-separated)", "");

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
    let oauth_redirect_path = matches.opt_str("oauth_redirect_path").unwrap();
    oauth_config.redirect_url = format!("https://{}{}", matches.opt_str("host_and_port").unwrap(), oauth_redirect_path);

    let whitelisted_domains = matches.opt_str("d").unwrap()
        .split(",")
        .map(|x| x.to_string())
        .collect();

    let host_and_port = format!("{}:{}", interface, port);
    return (host_and_port, ssl, oauth_config, oauth_redirect_path, whitelisted_domains);
}

struct Handler {
    oauth_config: oauth2::Config,
    oauth_redirect_path: String,
    whitelisted_domains: HashSet<String>,
    redirect_uris: Arc<Mutex<HashMap<String, String>>>,
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
                hyper::Get => self.handle_oauth_authorize_request(qs, res),
                _ => self.not_allowed(res),
            },
            _ => {
                if path == &self.oauth_redirect_path[..] {
                    match req.method {
                        hyper::Get => match qs {
                            Some(q) => self.handle_oauth_exchange_request(&q, res),
                            None => self.bad_request(res, "Missing querstring"),
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
            get_json_string!(body, "committer_name"),
            get_json_string!(body, "committer_email"),
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
            get_json_string!(body, "password"),
            get_json_string!(body, "committer_name"),
            get_json_string!(body, "committer_email"),
        );
    }

    fn handle_oauth_authorize_request(&self, qs: Option<String>, mut res: Response) {
        let uuid = Uuid::new_v4().to_hyphenated_string();

        let redirect_uri = self.get_redirect_uri(&qs);

        if redirect_uri.is_none() {
            self.bad_request(res, "Missing or bad redirect_uri");
            return;
        }

        let mut uris = self.redirect_uris.lock().unwrap();
        uris.insert(uuid.clone(), redirect_uri.unwrap().to_owned());

        // TODO: Implement clone for oauth2::Config
        let mut oauth_config = oauth2::Config::new(
            &self.oauth_config.client_id,
            &self.oauth_config.client_secret,
            &self.oauth_config.auth_url.to_string(),
            &self.oauth_config.token_url.to_string(),
        );
        oauth_config.redirect_url = self.oauth_config.redirect_url.clone();
        oauth_config.scopes.extend(self.get_scopes(&qs));

        let _ = *res.status_mut() = StatusCode::Found;
        res.headers_mut().set(header::Location(oauth_config.authorize_url(uuid).to_string()));
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
        let state = match obj.find("state") {
            Some(c) => match c.as_string() {
                Some(c) => c,
                None => { self.error(res, "state not a string"); return },
            },
            None => { self.error(res, "No state present"); return },
        };
        let token = self.oauth_config.exchange(code.to_owned());
        match token {
            Ok(tok) => self.respond_with_token(res, state, &tok.access_token),
            Err(tok) => self.error(res, &format!("Error exchanging token: {}", tok)),
        };
    }

    fn respond_with_token(&self, mut res: Response, uuid: &str, token: &str) {
        let mut uris = self.redirect_uris.lock().unwrap();
        match uris.remove(uuid) {
            Some(uri) => {
                let _ = *res.status_mut() = StatusCode::Found;
                // TODO: Form URI better
                res.headers_mut().set(header::Location(format!("{}?token={}", uri, token)));
            },
            None => { self.bad_request(res, "Unknown caller"); },
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

    fn get_redirect_uri(&self, qs: &Option<String>) -> Option<String> {
        let string = self.get_string_qs(qs, "redirect_uri");
        if string.is_none() {
            return string
        }

        let url = Url::parse(&string.clone().unwrap());
        match url {
            Ok(u) => {
                if &u.scheme != "https" {
                    return None;
                }
                let domain = u.domain();
                if domain.is_none() {
                    return None;
                }
                if !self.is_whitelisted_domain(domain.unwrap()) {
                    return None;
                }
            },
            Err(_) => { return None; },
        };
        return string;
    }

    fn is_whitelisted_domain(&self, domain: &str) -> bool {
        return self.whitelisted_domains.contains(&domain.to_owned());
    }

    fn get_scopes(&self, qs: &Option<String>) -> Vec<String> {
        let val = self.get_string_qs(qs, "scopes")
            .clone()
            .unwrap_or("".to_owned());
        return val
            .split(",")
            .map(|x| x.to_string())
            .collect();
    }

    fn get_string_qs(&self, qs: &Option<String>, key: &str) -> Option<String> {
        let kv = match qs.clone() {
            Some(q) => match parse(&q) {
                Ok(kv) => kv,
                Err(_) => return None,
            },
            None => return None,
        };
        return kv.find(key)
            .and_then(|v| v.as_string())
            .and_then(|v| Some(v.to_owned().clone()));
    }

    fn error(&self, mut res: Response, description: &str) {
        let _ = *res.status_mut() = StatusCode::InternalServerError;
        self.send_json(res, &ErrorResponse { message: description });
    }

    fn bad_request(&self, mut res: Response, reason: &str) {
        let _ = *res.status_mut() = StatusCode::BadRequest;
        self.send_json(res, &ErrorResponse { message: &format!("Bad request: {}", reason) });
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
