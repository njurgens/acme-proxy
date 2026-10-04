//! A mock of the Azure DNS management plane for the e2e lab.
//!
//! One process plays the three roles the relay's `azure` provider talks to:
//!
//! - the local OIDC issuer (Keycloak):
//!   `POST /realms/{realm}/protocol/openid-connect/token` mints a short-lived
//!   JWT from the client's basic-auth credentials;
//! - the Entra authority: `POST /{tenant}/oauth2/v2.0/token` exchanges that
//!   JWT (a `client_assertion`) for a management token;
//! - the ARM management plane: `GET`/`PUT`/`DELETE` of a zone's TXT record
//!   sets, with the ETag / `If-Match` / `If-None-Match` conditional-write
//!   semantics the provider relies on.
//!
//! Every successful write is mirrored into the lab's BIND over RFC 2136, so
//! the upstream CA's DNS lookup sees the record the way it would see a real
//! Azure zone: the mock's record store is the management plane, BIND is the
//! zone as the world sees it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State as AxumState};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use base64::prelude::*;
use hickory_proto::op::{Message, ResponseCode, update_message};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet as HxRecordSet, RecordType, TSigner};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde_json::{json, Value};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

/// One TXT record set in the mock's management plane.
#[derive(Clone)]
struct TxtRecordSet {
    etag: u64,
    ttl: u64,
    /// The `TXTRecords` elements: each an array of character-strings.
    txt: Vec<Vec<String>>,
}

#[derive(Default)]
struct Store {
    /// zone -> record name -> record set
    zones: HashMap<String, HashMap<String, TxtRecordSet>>,
}

struct MockState {
    store: RwLock<Store>,
    etags: AtomicU64,
    bind: Arc<Bind>,
    /// The last management token issued, so a test can assert what the relay
    /// was expected to present.
    last_entra_token: RwLock<String>,
}

// --- the two token endpoints ----------------------------------------------

/// The Keycloak stand-in: any basic-authed `client_credentials` request is
/// answered with a fresh JWT. The relay never validates the JWT — Entra
/// does — so the mock only checks the request is shaped like one.
async fn issuer_token(AxumState(state): AxumState<Arc<MockState>>, body: axum::body::Bytes) -> Response {
    let form = parse_form(&String::from_utf8_lossy(&body));
    if form.get("grant_type").map(|v| v.as_str()) != Some("client_credentials") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "unsupported_grant_type" })),
        )
            .into_response();
    }
    let counter = state.etags.fetch_add(1, Ordering::SeqCst);
    let jwt = fake_jwt(counter);
    (
        StatusCode::OK,
        Json(json!({
            "access_token": jwt,
            "expires_in": 300,
            "token_type": "Bearer"
        })),
    )
        .into_response()
}

/// A compact JWT with the three segments the exchange passes around. The
/// payload names the client, so a test can tell which credential minted it.
fn fake_jwt(counter: u64) -> String {
    let b64 = |value: &str| {
        BASE64_URL_SAFE_NO_PAD
            .encode(value.as_bytes())
            .replace('=', "")
    };
    let header = b64(r#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = b64(&format!(
        r#"{{"sub":"e2e-service-account","aud":"e2e-entra-app","iat":{counter}}}"#
    ));
    format!("{header}.{payload}.signature")
}

/// The Entra stand-in: a `client_assertion` exchange for a management token.
/// It refuses a request that is not shaped like one, so a relay that stopped
/// sending the assertion fails the way it would against the real authority.
async fn entra_token(
    AxumState(state): AxumState<Arc<MockState>>,
    Path(tenant): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let form = parse_form(&String::from_utf8_lossy(&body));
    let assertion = form.get("client_assertion").cloned().unwrap_or_default();
    let assertion_type = form.get("client_assertion_type").cloned().unwrap_or_default();
    if assertion.split('.').count() != 3
        || assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_client_assertion",
                "error_description": format!("the assertion is not a JWT (tenant {tenant})")
            })),
        )
            .into_response();
    }
    let counter = state.etags.fetch_add(1, Ordering::SeqCst);
    let token = format!("arm-token-{counter}");
    *state.last_entra_token.write().await = token.clone();
    (
        StatusCode::OK,
        Json(json!({
            "access_token": token,
            "expires_in": 3599,
            "token_type": "Bearer"
        })),
    )
        .into_response()
}

/// Percent-decodes an `application/x-www-form-urlencoded` body into a map.
fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((key.to_string(), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            out.push(u8::from_str_radix(hex, 16).unwrap_or(bytes[i]));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// --- the ARM management plane ----------------------------------------------

/// `GET …/TXT/{name}`: the record set, or a 404.
async fn arm_get(
    AxumState(state): AxumState<Arc<MockState>>,
    Path((zone, name)): Path<(String, String)>,
) -> Response {
    let store = state.store.read().await;
    match store.zones.get(&zone).and_then(|records| records.get(&name)) {
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": { "code": "RecordSetNotFound", "message": "no such record set" }
            })),
        )
            .into_response(),
        Some(record) => etagged(
            StatusCode::OK,
            record_body(&zone, &name, record),
            record.etag,
        ),
    }
}

/// The resource JSON for a record set: the etag top-level, the properties
/// beneath, the shape the 2023-07-01-preview dialect uses.
fn record_body(zone: &str, name: &str, record: &TxtRecordSet) -> Value {
    json!({
        "id": format!("/dnszones/{}/TXT/{}", zone, name),
        "name": name,
        "etag": format!("0x{:08x}", record.etag),
        "properties": {
            "TTL": record.ttl,
            "TXTRecords": record.txt.iter().map(|value| json!({ "value": value })).collect::<Vec<_>>()
        }
    })
}

/// A 200/201 answer with the etag both in the body and the `ETag` header —
/// the way the real service carries it, and the header is what a client
/// presents back in `If-Match`.
fn etagged(status: StatusCode, body: Value, etag: u64) -> Response {
    let mut response = (status, Json(body)).into_response();
    if let Ok(value) = format!("0x{etag:08x}").parse() {
        response.headers_mut().insert(axum::http::header::ETAG, value);
    }
    response
}

/// `PUT …/TXT/{name}`: a conditional write. `If-None-Match: *` creates (412
/// if one appeared), `If-Match: <etag>` updates (412 if the etag moved).
/// A successful write is mirrored into BIND before the answer goes out, so
/// the zone is visible to the world by the time the caller proceeds.
async fn arm_put(
    AxumState(state): AxumState<Arc<MockState>>,
    Path((zone, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let if_none_match = header_value(&headers, "if-none-match");
    let if_match = header_value(&headers, "if-match");
    let body: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": { "code": "BadBody", "message": error.to_string() } })),
            )
                .into_response();
        }
    };

    let mut store = state.store.write().await;
    let zone_records = store.zones.entry(zone.clone()).or_default();

    if if_none_match.as_deref() == Some("*") {
        if zone_records.contains_key(&name) {
            return conflict("a record set already exists at that name");
        }
        let etag = state.etags.fetch_add(1, Ordering::SeqCst);
        let record = record_from_body(etag, &body);
        state.bind.mirror(&name, &[], &record.txt).await;
        zone_records.insert(name, record);
        return etagged(
            StatusCode::CREATED,
            json!({ "etag": format!("0x{etag:08x}") }),
            etag,
        );
    }

    let Some(expected) = if_match else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": { "code": "MissingConditionalHeader", "message": "neither If-Match nor If-None-Match" }
            })),
        )
            .into_response();
    };
    match zone_records.get_mut(&name) {
        None => return conflict("no record set exists at that name to match"),
        Some(record) if record.etag != parse_etag(&expected) => {
            return conflict("the etag no longer matches");
        }
        Some(record) => {
            let etag = state.etags.fetch_add(1, Ordering::SeqCst);
            let old_txt = record.txt.clone();
            let new = record_from_body(etag, &body);
            state.bind.mirror(&name, &old_txt, &new.txt).await;
            *record = new;
            return etagged(
                StatusCode::OK,
                json!({ "etag": format!("0x{etag:08x}") }),
                etag,
            );
        }
    }
}

/// `DELETE …/TXT/{name}`: conditional on `If-Match`; a 404 (already gone)
/// is the success the trait's idempotent delete wants.
async fn arm_delete(
    AxumState(state): AxumState<Arc<MockState>>,
    Path((zone, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(expected) = header_value(&headers, "if-match") else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "code": "MissingConditionalHeader", "message": "If-Match is required" } })),
        )
            .into_response();
    };
    let mut store = state.store.write().await;
    // Read the etag and the values out first: the removal below re-borrows
    // the same map, and the two borrows must not overlap.
    let (gone, matches) =
        match store.zones.get_mut(&zone).and_then(|records| records.get_mut(&name)) {
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": { "code": "RecordSetNotFound", "message": "no such record set" } })),
                )
                    .into_response();
            }
            Some(record) => (record.txt.clone(), record.etag == parse_etag(&expected)),
        };
    if !matches {
        return conflict("the etag no longer matches");
    }
    if let Some(records) = store.zones.get_mut(&zone) {
        records.remove(&name);
    }
    state.bind.mirror(&name, &gone, &[]).await;
    (StatusCode::NO_CONTENT,).into_response()
}

fn conflict(message: &str) -> Response {
    (
        StatusCode::PRECONDITION_FAILED,
        Json(json!({ "error": { "code": "RecordSetConflict", "message": message } })),
    )
        .into_response()
}

/// The `TXTRecords` of a PUT body, as the mock's store holds them.
fn record_from_body(etag: u64, body: &Value) -> TxtRecordSet {
    let properties = body.get("properties").cloned().unwrap_or(Value::Null);
    let ttl = properties
        .get("TTL")
        .and_then(Value::as_u64)
        .unwrap_or(60);
    let mut txt = Vec::new();
    if let Some(Value::Array(records)) = properties.get("TXTRecords") {
        for record in records {
            if let Some(Value::Array(value)) = record.get("value") {
                let strings = value
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                if !strings.is_empty() {
                    txt.push(strings);
                }
            }
        }
    }
    TxtRecordSet { etag, ttl, txt }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// The ETag the client presented, as the counter that minted it.
fn parse_etag(presented: &str) -> u64 {
    presented
        .trim_start_matches("0x")
        .trim_start_matches('"')
        .trim_end_matches('"')
        .parse::<u64>()
        .unwrap_or(u64::MAX)
}

// --- the RFC 2136 mirror into the lab's BIND -------------------------------

/// The lab's BIND, the zone the mock's writes must become visible in.
struct Bind {
    server: SocketAddr,
    zone: Name,
    signer: TSigner,
}

impl Bind {
    fn new(server: SocketAddr, zone: &str, key_name: &str, secret: &[u8]) -> Self {
        let zone = Name::from_utf8(zone).expect("the lab zone is a DNS name");
        let key_name = Name::from_utf8(key_name).expect("the lab key name is a DNS name");
        let signer = TSigner::new(secret.to_vec(), TsigAlgorithm::HmacSha256, key_name, 300)
            .expect("a TSIG signer builds from a non-empty secret");
        Self {
            server,
            zone,
            signer,
        }
    }

    /// Mirrors a record-set change into the zone: the values in `old` that
    /// are gone are deleted by rdata, the values in `new` that are not yet
    /// there are appended. A no-op on both sides sends nothing.
    async fn mirror(&self, name: &str, old: &[Vec<String>], new: &[Vec<String>]) {
        let name = match Name::from_utf8(&format!("{name}.{}.", self.zone.to_utf8().trim_end_matches('.'))) {
            Ok(name) => name,
            Err(error) => {
                eprintln!("azure-mock: refusing to mirror {name}: {error}");
                return;
            }
        };
        let removed: Vec<&str> = old
            .iter()
            .flat_map(|value| value.iter().map(String::as_str))
            .filter(|value| !new.iter().any(|record| record.iter().any(|s| s.as_str() == *value)))
            .collect();
        let added: Vec<&str> = new
            .iter()
            .flat_map(|value| value.iter().map(String::as_str))
            .filter(|value| !old.iter().any(|record| record.iter().any(|s| s.as_str() == *value)))
            .collect();

        if !removed.is_empty() {
            let mut rrset = HxRecordSet::new(name.clone(), RecordType::TXT, 0);
            for value in removed {
                let mut record = Record::from_rdata(
                    name.clone(),
                    0,
                    RData::TXT(TXT::new(vec![value.to_string()])),
                );
                record.dns_class = DNSClass::IN;
                rrset.insert(record, 0);
            }
            let message = update_message::delete_by_rdata(rrset, self.zone.clone(), true);
            self.send(message).await;
        }
        if !added.is_empty() {
            let mut rrset = HxRecordSet::new(name.clone(), RecordType::TXT, 60);
            for value in added {
                let mut record = Record::from_rdata(
                    name.clone(),
                    60,
                    RData::TXT(TXT::new(vec![value.to_string()])),
                );
                record.dns_class = DNSClass::IN;
                rrset.insert(record, 0);
            }
            let message = update_message::append(rrset, self.zone.clone(), false, true);
            self.send(message).await;
        }
    }

    /// Signs and sends one update, succeeding only on a NOERROR answer
    /// verified against the key — the same rule the relay's own rfc2136
    /// provider holds.
    async fn send(&self, mut message: Message) {
        let id = message.id;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let Some(mut verifier) = message
            .finalize(&self.signer, now)
            .ok()
            .and_then(|v| v)
        else {
            eprintln!("azure-mock: signing the BIND update failed");
            return;
        };
        let bytes = match message.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("azure-mock: encoding the BIND update failed: {error}");
                return;
            }
        };

        let answer = match tokio::time::timeout(std::time::Duration::from_secs(5), self.exchange(&bytes)).await
        {
            Ok(Ok(answer)) => answer,
            Ok(Err(error)) => {
                eprintln!("azure-mock: the BIND update failed: {error}");
                return;
            }
            Err(_) => {
                eprintln!("azure-mock: the BIND update timed out");
                return;
            }
        };
        let response = match Message::from_bytes(&answer) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("azure-mock: the BIND answer is not a message: {error}");
                return;
            }
        };
        if response.id != id {
            eprintln!("azure-mock: the BIND answer's id does not match");
            return;
        }
        if response.response_code != ResponseCode::NoError {
            eprintln!(
                "azure-mock: BIND refused the update: {}",
                response.response_code
            );
            return;
        }
        if let Err(error) = verifier.verify(&answer) {
            eprintln!("azure-mock: the BIND answer is not TSIG-verified: {error}");
        }
    }

    /// UDP first, the TCP retry on truncation — the ordinary DNS fallback.
    async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|error| format!("binding UDP: {error}"))?;
        socket
            .connect(self.server)
            .await
            .map_err(|error| format!("connecting to BIND: {error}"))?;
        socket
            .send(request)
            .await
            .map_err(|error| format!("sending to BIND: {error}"))?;

        let mut buffer = vec![0u8; 4096];
        let read = socket
            .recv(&mut buffer)
            .await
            .map_err(|error| format!("no answer from BIND: {error}"))?;
        buffer.truncate(read);

        if Message::from_bytes(&buffer)
            .map(|message| message.truncation)
            .unwrap_or(false)
        {
            return self.exchange_tcp(request).await;
        }
        Ok(buffer)
    }

    async fn exchange_tcp(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = TcpStream::connect(self.server)
            .await
            .map_err(|error| format!("connecting to BIND over TCP: {error}"))?;
        let length = u16::try_from(request.len())
            .map_err(|_| "the update is too large for TCP framing".to_string())?;
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|error| format!("writing to BIND: {error}"))?;
        stream
            .write_all(request)
            .await
            .map_err(|error| format!("writing to BIND: {error}"))?;

        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|error| format!("reading from BIND: {error}"))?;
        let mut response = vec![0u8; u16::from_be_bytes(length) as usize];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|error| format!("reading from BIND: {error}"))?;
        Ok(response)
    }
}

// --- the process -----------------------------------------------------------

#[tokio::main]
async fn main() {
    let bind_host = std::env::var("BIND_HOST").unwrap_or_else(|error| {
        eprintln!("azure-mock: BIND_HOST is not set: {error}");
        std::process::exit(2);
    });
    let bind_server: SocketAddr = format!("{bind_host}:53")
        .parse()
        .expect("BIND_HOST:53 is a socket address");
    // The lab's BIND: one zone, one TSIG key, both fixed by the lab.
    let bind = Arc::new(Bind::new(
        bind_server,
        "lab.",
        "tsig-key.",
        b"0123456789abcdef0123456789abcdef0123456789abcdef",
    ));

    let state = Arc::new(MockState {
        store: RwLock::new(Store::default()),
        etags: AtomicU64::new(1),
        bind,
        last_entra_token: RwLock::new(String::new()),
    });

    let app = Router::new()
        .route(
            "/realms/{realm}/protocol/openid-connect/token",
            post(issuer_token),
        )
        .route("/{tenant}/oauth2/v2.0/token", post(entra_token))
        .route(
            "/arm/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/dnszones/{zone}/TXT/{name}",
            get(arm_get).merge(post(arm_put)).merge(delete(arm_delete)),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("the mock binds 8080");
    println!("azure-mock listening on 8080; BIND at {bind_host}:53");
    axum::serve(listener, app).await.expect("the mock served");
}
