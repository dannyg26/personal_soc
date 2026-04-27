use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use monitor_core::persistence::Database;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};
use url::form_urlencoded;

use crate::credential_vault;
use crate::credential_vault::VaultAccessController;

#[derive(Clone)]
pub struct BrowserBridgeRuntime {
    port: u16,
    running: Arc<AtomicBool>,
}

impl BrowserBridgeRuntime {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::Relaxed);
    }
}

#[derive(Deserialize)]
struct PairRequest {
    #[serde(rename = "pairCode")]
    pair_code: String,
}

#[derive(Deserialize)]
struct SaveCredentialRequest {
    origin: String,
    username: String,
    password: String,
    #[serde(rename = "siteLabel")]
    site_label: Option<String>,
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

pub fn spawn(
    runtime: BrowserBridgeRuntime,
    db: Arc<Database>,
    vault_access: VaultAccessController,
) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(("127.0.0.1", runtime.port())) {
            Ok(listener) => listener,
            Err(err) => {
                runtime.set_running(false);
                error!(
                    "Browser credential bridge failed to bind to 127.0.0.1:{}: {}",
                    runtime.port(),
                    err
                );
                return;
            }
        };

        runtime.set_running(true);
        info!(
            "Browser credential bridge listening on http://127.0.0.1:{}",
            runtime.port()
        );

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let db = db.clone();
                    let vault_access = vault_access.clone();
                    std::thread::spawn(move || {
                        if let Err(err) = handle_connection(stream, db, vault_access) {
                            warn!("Browser bridge request failed: {}", err);
                        }
                    });
                }
                Err(err) => warn!("Browser bridge connection failed: {}", err),
            }
        }

        runtime.set_running(false);
    });
}

fn handle_connection(
    mut stream: TcpStream,
    db: Arc<Database>,
    _vault_access: VaultAccessController,
) -> Result<(), String> {
    let request = read_request(&stream)?;
    let response = route_request(&db, request);
    write_response(&mut stream, response)
}

fn route_request(db: &Database, request: HttpRequest) -> HttpResponse {
    if request.method == "OPTIONS" {
        return HttpResponse::no_content();
    }

    if request.method == "GET" && request.path == "/health" {
        return HttpResponse::ok(json!({ "ok": true }));
    }

    if request.method == "POST" && request.path == "/api/pair" {
        let body: PairRequest = match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(_) => {
                return HttpResponse::bad_request(
                    "Threat Guard could not read the pairing request.",
                )
            }
        };

        return match credential_vault::pair_extension(db, &body.pair_code) {
            Ok(token) => HttpResponse::ok(json!({ "token": token })),
            Err(err) => HttpResponse::unauthorized(&err),
        };
    }

    let Some(token) = bearer_token(&request.headers) else {
        return HttpResponse::unauthorized(
            "Threat Guard pairing is required before the browser extension can connect.",
        );
    };

    match credential_vault::validate_extension_token(db, &token) {
        Ok(true) => {}
        Ok(false) => {
            return HttpResponse::unauthorized(
                "Threat Guard rejected the browser token. Pair the extension again.",
            );
        }
        Err(err) => return HttpResponse::server_error(&err),
    }

    if request.method == "GET" && request.path.starts_with("/api/credentials/availability") {
        let origin = query_value(&request.path, "origin").unwrap_or_default();

        return match credential_vault::has_autofill_credentials_for_origin(db, &origin) {
            Ok(has_credentials) => {
                HttpResponse::ok(json!({ "hasCredentials": has_credentials }))
            }
            Err(err) => HttpResponse::bad_request(&err),
        };
    }

    if request.method == "GET" && request.path.starts_with("/api/credentials") {
        let origin = query_value(&request.path, "origin").unwrap_or_default();
        let passcode = request
            .headers
            .get("x-threat-guard-vault-passcode")
            .map(String::as_str)
            .unwrap_or_default();

        if passcode.trim().is_empty() {
            return HttpResponse::forbidden(
                credential_vault::VAULT_AUTOFILL_UNLOCK_REQUIRED_MESSAGE,
            );
        }

        if let Err(err) = credential_vault::confirm_passcode(db, passcode) {
            return HttpResponse::forbidden(&err);
        }

        return match credential_vault::list_autofill_credentials_for_origin(db, &origin) {
            Ok(credentials) => HttpResponse::ok(json!({ "credentials": credentials })),
            Err(err) => HttpResponse::bad_request(&err),
        };
    }

    if request.method == "POST" && request.path == "/api/credentials" {
        let body: SaveCredentialRequest = match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(_) => {
                return HttpResponse::bad_request(
                    "Threat Guard could not read the credential payload.",
                )
            }
        };

        return match credential_vault::save_credential(
            db,
            &body.origin,
            body.site_label.as_deref(),
            &body.username,
            &body.password,
            "browser_extension",
        ) {
            Ok(credential) => HttpResponse::ok(json!({ "credential": credential })),
            Err(err) => HttpResponse::bad_request(&err),
        };
    }

    HttpResponse::not_found()
}

fn read_request(stream: &TcpStream) -> Result<HttpRequest, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|err| err.to_string())?);

    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|err| err.to_string())?;

    if request_line.trim().is_empty() {
        return Err("Received an empty HTTP request.".to_string());
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Threat Guard received a malformed HTTP request line.".to_string());
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|err| err.to_string())?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = vec![0; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|err| err.to_string())?;
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn bearer_token(headers: &HashMap<String, String>) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
}

fn query_value(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?')?.1;
    form_urlencoded::parse(query.as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

struct HttpResponse {
    status_code: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn ok(value: serde_json::Value) -> Self {
        Self {
            status_code: 200,
            body: serde_json::to_vec(&value)
                .unwrap_or_else(|_| b"{\"error\":\"serialization_failed\"}".to_vec()),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status_code: 400,
            body: serde_json::to_vec(&json!({ "error": message })).unwrap_or_default(),
        }
    }

    fn unauthorized(message: &str) -> Self {
        Self {
            status_code: 401,
            body: serde_json::to_vec(&json!({ "error": message })).unwrap_or_default(),
        }
    }

    fn forbidden(message: &str) -> Self {
        Self {
            status_code: 403,
            body: serde_json::to_vec(&json!({ "error": message })).unwrap_or_default(),
        }
    }

    fn not_found() -> Self {
        Self {
            status_code: 404,
            body: serde_json::to_vec(&json!({ "error": "Not found" })).unwrap_or_default(),
        }
    }

    fn server_error(message: &str) -> Self {
        Self {
            status_code: 500,
            body: serde_json::to_vec(&json!({ "error": message })).unwrap_or_default(),
        }
    }

    fn no_content() -> Self {
        Self {
            status_code: 204,
            body: Vec::new(),
        }
    }
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) -> Result<(), String> {
    let reason = match response.status_code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Internal Server Error",
    };

    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nConnection: close\r\n\r\n",
        response.status_code,
        reason,
        response.body.len()
    );

    stream
        .write_all(headers.as_bytes())
        .map_err(|err| err.to_string())?;
    if !response.body.is_empty() {
        stream
            .write_all(&response.body)
            .map_err(|err| err.to_string())?;
    }
    stream.flush().map_err(|err| err.to_string())
}
