//! The `azure` dns-01 provider: publishing the upstream CA's `_acme-challenge`
//! TXT records through the Azure DNS REST API.
//!
//! ## Authentication: a federated credential
//!
//! The relay's host is a private machine: it has no public identity and no
//! Azure credential of its own. What it does have is a client at the local
//! OIDC issuer (Keycloak) — a confidential client whose service account an
//! operator has registered as a *federated credential* on an Entra
//! application. The exchange this module performs is therefore two hops:
//!
//! 1. the client's id and secret mint a short-lived JWT at the issuer
//!    (the `client_credentials` grant);
//! 2. that JWT is presented to Entra as a `client_assertion`, and Entra —
//!    which validates the assertion against the registered credential —
//!    answers with a management token for `https://management.azure.com`.
//!
//! The only long-lived secret is the client's. The JWT lives minutes and the
//! management token about an hour, and is cached until close to its expiry.
//!
//! ## The record's content is not defined here
//!
//! [`acme_proxy_net::challenge::dns_01`] owns both the record name and the
//! digest computation, and this module calls into it — the same arrangement
//! as [`super::dns01`].
//!
//! ## Concurrency
//!
//! The zone is not private to this process: another relay instance, the
//! portal, or an automation may write the same record. Every read-modify-write
//! is therefore conditional — `If-None-Match: *` on create, `If-Match` with
//! the record's ETag on update and delete — and a `412` means "the world
//! moved; read it again and try the change again", in a bounded loop. The
//! per-name lock keeps this process's own orders from racing each other; it
//! is an optimisation, not the safety mechanism.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::prelude::*;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use rustls_pki_types::CertificateDer;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use url::Url;

use acme_proxy_core::config::AzureDnsConfig;
use acme_proxy_net::egress::Egress;
use acme_proxy_net::http_client::{self, Endpoint, Outbound, MAX_RESPONSE_BYTES};

use super::dns01::DnsUpdater;

/// Budget for one HTTP exchange, token mint or ARM call alike.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a minted management token is kept before re-exchanging. Entra
/// issues about an hour; refreshing at fifty leaves margin for the clock skew
/// between this process and the token's issuer.
const TOKEN_REFRESH_AFTER: Duration = Duration::from_secs(50 * 60);

/// TTL, in seconds, on a challenge record this process creates.
const CHALLENGE_TTL: u64 = 60;

/// How many times a conditional write may be re-read and re-applied after a
/// `412` before the change is given up on.
const MAX_CONFLICT_ATTEMPTS: usize = 3;

/// The `scope` the management token is issued for: the Azure Resource Manager.
const ARM_SCOPE: &str = "https://management.azure.com/.default";

/// The assertion type that says "this JWT is the client's own credential".
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The Entra endpoint that exchanges a federated assertion for a token.
fn entra_token_url(tenant: &str) -> Url {
    Url::parse(&format!(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    ))
    .expect("a well-formed tenant cannot build a malformed URL")
}

/// A source of Azure Resource Manager tokens, minted through a federated
/// credential: a short-lived JWT from the local OIDC issuer (Keycloak),
/// exchanged at Microsoft Entra for a management token.
pub struct FederatedTokenSource {
    /// The local issuer's realm URL; the token endpoint is joined onto it.
    issuer: Url,
    /// The Entra token endpoint for the configured tenant.
    entra: Url,
    /// The confidential client at the issuer.
    client_id: String,
    /// SENSITIVE: the client's secret, spent once per mint.
    client_secret: String,
    /// The Entra application the assertion is federated to.
    entra_client_id: String,
    /// Trust for the issuer: public roots, plus `issuer_ca_file`'s when set.
    issuer_tls: Arc<rustls::ClientConfig>,
    /// Trust for Entra and ARM: public roots only.
    public_tls: Arc<rustls::ClientConfig>,
    outbound: Outbound,
    timeout: Duration,
    /// The cached management token and when it was minted. The lock is held
    /// across a mint, so two concurrent callers pay for one exchange and the
    /// second finds the first's result.
    cached: Mutex<Option<(String, Instant)>>,
}

impl FederatedTokenSource {
    /// Validates the configuration and builds the two trust stores.
    ///
    /// No network I/O: the issuer may be down at startup and up later, and
    /// the first exchange is the moment a credential problem should surface,
    /// with the issuer's own error text rather than a connect failure.
    pub fn from_config(cfg: &AzureDnsConfig, egress: &Egress) -> anyhow::Result<Self> {
        for (field, value) in [
            ("issuer", &cfg.issuer),
            ("client_id", &cfg.client_id),
            ("client_secret", &cfg.client_secret),
            ("entra_tenant_id", &cfg.entra_tenant_id),
            ("entra_client_id", &cfg.entra_client_id),
        ] {
            if value.is_empty() {
                anyhow::bail!("signer.relay.dns01.azure.{field} is not set");
            }
        }
        let issuer = Url::parse(cfg.issuer.trim())
            .map_err(|error| {
                anyhow::anyhow!(
                    "signer.relay.dns01.azure.issuer ({}) is not a URL: {error}",
                    cfg.issuer
                )
            })?;
        if !matches!(issuer.scheme(), "http" | "https") {
            anyhow::bail!(
                "signer.relay.dns01.azure.issuer ({}) must be http or https",
                cfg.issuer
            );
        }

        Ok(Self {
            issuer,
            entra: entra_token_url(&cfg.entra_tenant_id),
            client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret.clone(),
            entra_client_id: cfg.entra_client_id.clone(),
            issuer_tls: Arc::new(issuer_tls_config(&cfg.issuer_ca_file)?),
            public_tls: Arc::new(http_client::webpki_tls_config()),
            outbound: egress.outbound(),
            timeout: REQUEST_TIMEOUT,
            cached: Mutex::new(None),
        })
    }

    /// A management token, minted if the cached one is close to expiry.
    pub async fn management_token(&self) -> Result<String, String> {
        let mut cache = self.cached.lock().await;
        if let Some((token, minted)) = cache.as_ref()
            && minted.elapsed() < TOKEN_REFRESH_AFTER
        {
            return Ok(token.clone());
        }

        let jwt = self.keycloak_jwt().await?;
        let (token, _expires_in) = self.entra_exchange(&jwt).await?;
        *cache = Some((token.clone(), Instant::now()));
        Ok(token)
    }

    /// Forgets the cached token, so the next `management_token` re-exchanges.
    /// Called when ARM answers `401`: the token was rejected, and the fix is a
    /// fresh one, not a retry of the same.
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }

    /// Mints a short-lived JWT at the local issuer with the client's own
    /// credentials (the `client_credentials` grant, basic-authenticated).
    async fn keycloak_jwt(&self) -> Result<String, String> {
        // Plain concatenation, not `Url::join`: the issuer is a realm URL and
        // the token endpoint is a fixed path beneath it — relative resolution
        // would replace the realm's last segment instead of appending.
        let url = Url::parse(&format!(
            "{}/protocol/openid-connect/token",
            self.issuer.as_str().trim_end_matches('/')
        ))
        .map_err(|error| format!("issuer URL: {error}"))?;
        let credential = BASE64_STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret));
        let (status, body) = self
            .post_form(&url, &self.issuer_tls, Some(&format!("Basic {credential}")), "grant_type=client_credentials")
            .await?;
        if !status.is_success() {
            return Err(self.exchange_failure("the issuer", &body));
        }
        body.get("access_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| self.exchange_failure("the issuer", &body))
    }

    /// Exchanges the assertion for a management token at Entra.
    async fn entra_exchange(&self, assertion: &str) -> Result<(String, u64), String> {
        let form = [
            "grant_type=client_credentials",
            &format!("client_id={}", form_encode(&self.entra_client_id)),
            &format!("client_assertion_type={}", form_encode(CLIENT_ASSERTION_TYPE)),
            &format!("client_assertion={}", form_encode(assertion)),
            &format!("scope={}", form_encode(ARM_SCOPE)),
        ]
        .join("&");
        let (status, body) = self
            .post_form(&self.entra, &self.public_tls, None, &form)
            .await?;
        if !status.is_success() {
            return Err(self.exchange_failure("Entra", &body));
        }
        let token = body
            .get("access_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| self.exchange_failure("Entra", &body))?;
        let expires_in = body.get("expires_in").and_then(Value::as_u64).unwrap_or(0);
        Ok((token, expires_in))
    }

    /// The words a refused exchange gets, with the server's own error text.
    fn exchange_failure(&self, where_: &str, body: &Value) -> String {
        let detail = body
            .get("error_description")
            .or_else(|| body.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("no error text in the answer");
        format!("the token exchange at {where_} was refused: {detail}")
    }

    /// One `application/x-www-form-urlencoded` POST over the crate's outbound
    /// plumbing, returning the status and the decoded body — a non-success
    /// included, so the caller can quote the server's own error text.
    async fn post_form(
        &self,
        url: &Url,
        tls: &Arc<rustls::ClientConfig>,
        authorization: Option<&str>,
        form: &str,
    ) -> Result<(StatusCode, Value), String> {
        let endpoint = Endpoint::from_url(url).map_err(|error| format!("outbound: {error}"))?;
        let mut connection = self
            .outbound
            .connect(&endpoint, tls)
            .await
            .map_err(|error| format!("connecting to {}: {error}", endpoint.host))?;

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(connection.request_target(url))
            .header(hyper::header::HOST, endpoint.authority())
            .header(hyper::header::USER_AGENT, "acme-proxy")
            .header(hyper::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(credential) = authorization {
            builder = builder.header(hyper::header::AUTHORIZATION, credential);
        }
        let request = builder
            .body(Full::new(Bytes::copy_from_slice(form.as_bytes())))
            .map_err(|error| format!("building the token request: {error}"))?;

        let response = tokio::time::timeout(self.timeout, connection.send_request(request))
            .await
            .map_err(|_| format!("the token endpoint {url} timed out"))?
            .map_err(|error| format!("the token endpoint {url} dropped the connection: {error}"))?;

        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| format!("reading the token endpoint's answer: {error}"))?
            .to_bytes();
        let body = if body.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => json!({ "error": http_client::error_excerpt(&body) }),
            }
        };
        Ok((status, body))
    }
}

/// The trust store for the issuer: public roots, plus the roots of
/// `ca_file` when it is set — for an issuer on a private PKI.
fn issuer_tls_config(ca_file: &str) -> anyhow::Result<rustls::ClientConfig> {
    if ca_file.is_empty() {
        return Ok(http_client::webpki_tls_config());
    }
    let pem = std::fs::read_to_string(ca_file).map_err(|error| {
        anyhow::anyhow!(
            "signer.relay.dns01.azure.issuer_ca_file ({ca_file}) is not readable: {error}"
        )
    })?;
    let extra = pem_certs(&pem).map_err(|error| {
        anyhow::anyhow!("signer.relay.dns01.azure.issuer_ca_file ({ca_file}): {error}")
    })?;
    Ok(http_client::webpki_tls_config_with_extra_roots(&extra))
}

/// The `CERTIFICATE` blocks of a PEM file, in order.
fn pem_certs(pem: &str) -> anyhow::Result<Vec<CertificateDer<'_>>> {
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after_begin = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(end) = after_begin.find("-----END CERTIFICATE-----") else {
            anyhow::bail!("a BEGIN CERTIFICATE marker has no END marker");
        };
        let b64 = after_begin[..end].split_whitespace().collect::<String>();
        let der = BASE64_STANDARD
            .decode(&b64)
            .map_err(|error| anyhow::anyhow!("a certificate block is not base64: {error}"))?;
        certs.push(CertificateDer::from(der));
        rest = &after_begin[end + "-----END CERTIFICATE-----".len()..];
    }
    if certs.is_empty() {
        anyhow::bail!("no CERTIFICATE blocks found");
    }
    Ok(certs)
}

/// Percent-encodes a form field value (`application/x-www-form-urlencoded`).
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Publishes and retracts `_acme-challenge` TXT records in an Azure public
/// DNS zone, through the REST API and a [`FederatedTokenSource`].
pub struct AzureDnsUpdater {
    /// The zone, lowercased and without its trailing dot.
    zone: String,
    /// The zone's record-set base in the management plane.
    base: String,
    api_version: String,
    tokens: Arc<FederatedTokenSource>,
    tls: Arc<rustls::ClientConfig>,
    outbound: Outbound,
    timeout: Duration,
    /// One lock per record name, so this process's own orders on a shared
    /// name (an apex and a wildcard) cannot interleave their read-modify-writes.
    locks: std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

/// The outcome of a conditional `PUT` on a record set.
enum PutOutcome {
    /// `201`: the create landed.
    Created,
    /// `200`: the update landed.
    Updated,
    /// `412`: the ETag no longer matches; the caller re-reads and re-applies.
    Conflict,
}

/// The outcome of a conditional `DELETE` on a record set.
enum DeleteOutcome {
    /// The record is gone (or was already).
    Gone,
    /// `412`: the ETag no longer matches; the caller re-reads and re-applies.
    Conflict,
}

impl AzureDnsUpdater {
    /// Validates the configuration. The token source is built by the caller —
    /// it is shared, and its own `from_config` reports the credential
    /// problems — and only the ARM-side fields are checked here.
    pub fn from_config(cfg: &AzureDnsConfig, tokens: Arc<FederatedTokenSource>) -> anyhow::Result<Self> {
        for (field, value) in [
            ("zone", &cfg.zone),
            ("subscription_id", &cfg.subscription_id),
            ("resource_group", &cfg.resource_group),
            ("api_version", &cfg.api_version),
        ] {
            if value.is_empty() {
                anyhow::bail!("signer.relay.dns01.azure.{field} is not set");
            }
        }
        let zone = cfg.zone.trim_end_matches('.').to_ascii_lowercase();
        let base = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnszones/{}",
            cfg.subscription_id, cfg.resource_group, zone
        );
        let outbound = tokens.outbound.clone();
        Ok(Self {
            zone,
            base,
            api_version: cfg.api_version.clone(),
            tokens,
            tls: Arc::new(http_client::webpki_tls_config()),
            outbound,
            timeout: REQUEST_TIMEOUT,
            locks: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// The record's name in the zone's own terms: `@` at the apex, the bare
    /// label run below it otherwise.
    fn relative_name(&self, name: &str) -> Result<String, String> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name == self.zone {
            return Ok("@".to_string());
        }
        let suffix = format!(".{}", self.zone);
        if let Some(prefix) = name.strip_suffix(&suffix)
            && !prefix.is_empty()
        {
            return Ok(prefix.to_string());
        }
        Err(format!("{name} is outside the zone {}", self.zone))
    }

    fn name_lock(&self, name: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// The additive publish: read, and either the value is already there, or
    /// create it, or merge it in — each write conditional, each `412` a
    /// re-read.
    async fn upsert(&self, relative: &str, value: &str) -> Result<(), String> {
        for _attempt in 1..=MAX_CONFLICT_ATTEMPTS {
            match self.get_record(relative).await? {
                None => {
                    let body = json!({
                        "properties": {
                            "TTL": CHALLENGE_TTL,
                            "TXTRecords": [{ "value": [value] }]
                        }
                    });
                    if matches!(
                        self.put_record(relative, None, Some(&body)).await?,
                        PutOutcome::Created
                    ) {
                        return Ok(());
                    }
                }
                Some((etag, ttl, mut records)) => {
                    if merge_txt_records(&mut records, value) {
                        let body = json!({
                            "properties": { "TTL": ttl, "TXTRecords": records }
                        });
                        if matches!(
                            self.put_record(relative, Some(&etag), Some(&body)).await?,
                            PutOutcome::Updated
                        ) {
                            return Ok(());
                        }
                    } else {
                        return Ok(());
                    }
                }
            }
            // A conflict — or a create/update that answered the other way:
            // the world moved under the conditional write. Re-read and re-apply.
        }
        Err(format!(
            "Azure DNS {}/{}: {MAX_CONFLICT_ATTEMPTS} conflicting updates in a row; giving up",
            self.zone, relative
        ))
    }

    /// The retraction: read, and either the value is not there, or it is one
    /// of several and the record set is rewritten without it, or it is the
    /// last and the record set itself is deleted.
    async fn delete(&self, relative: &str, value: &str) -> Result<(), String> {
        for _attempt in 1..=MAX_CONFLICT_ATTEMPTS {
            match self.get_record(relative).await? {
                None => return Ok(()),
                Some((etag, ttl, mut records)) => {
                    if !remove_txt_records(&mut records, value) {
                        return Ok(());
                    }
                    if records.is_empty() {
                        match self.delete_record(relative, &etag).await? {
                            DeleteOutcome::Gone => return Ok(()),
                            DeleteOutcome::Conflict => continue,
                        }
                    } else {
                        let body = json!({
                            "properties": { "TTL": ttl, "TXTRecords": records }
                        });
                        match self.put_record(relative, Some(&etag), Some(&body)).await? {
                            PutOutcome::Updated => return Ok(()),
                            PutOutcome::Conflict => continue,
                            PutOutcome::Created => continue,
                        }
                    }
                }
            }
        }
        Err(format!(
            "Azure DNS {}/{}: {MAX_CONFLICT_ATTEMPTS} conflicting updates in a row; giving up",
            self.zone, relative
        ))
    }

    /// The record set at `relative`, or `None` for a `404`: its ETag, its TTL,
    /// and its `TXTRecords` elements.
    async fn get_record(&self, relative: &str) -> Result<Option<(String, u64, Vec<Value>)>, String> {
        let url = format!(
            "{}/TXT/{}?api-version={}",
            self.base, relative, self.api_version
        );
        let (status, etag, body) = self.arm_request(Method::GET, &url, None, false, None).await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::OK => {
                // The ETag rides on the response header; the resource body
                // carries the same value, and a reader of one or the other is
                // a valid server, so the body is the fallback.
                let etag = etag
                    .or_else(|| body.get("etag").and_then(Value::as_str).map(str::to_string))
                    .ok_or_else(|| "the zone's answer carried no ETag".to_string())?;
                let properties = body.get("properties").cloned().unwrap_or(Value::Null);
                let ttl = properties
                    .get("TTL")
                    .and_then(Value::as_u64)
                    .unwrap_or(CHALLENGE_TTL);
                let records = match properties.get("TXTRecords") {
                    Some(Value::Array(records)) => records.clone(),
                    _ => Vec::new(),
                };
                Ok(Some((etag, ttl, records)))
            }
            other => Err(self.arm_error("read", relative, other, &body)),
        }
    }

    /// A conditional `PUT` of the whole record set: `If-Match` with the
    /// record's ETag for an update, `If-None-Match: *` for a create.
    async fn put_record(
        &self,
        relative: &str,
        if_match: Option<&str>,
        body: Option<&Value>,
    ) -> Result<PutOutcome, String> {
        let url = format!(
            "{}/TXT/{}?api-version={}",
            self.base, relative, self.api_version
        );
        let (status, _etag, response) =
            self.arm_request(Method::PUT, &url, if_match, if_match.is_none(), body)
                .await?;
        match status {
            StatusCode::CREATED => Ok(PutOutcome::Created),
            StatusCode::OK => Ok(PutOutcome::Updated),
            StatusCode::PRECONDITION_FAILED => Ok(PutOutcome::Conflict),
            other => Err(self.arm_error("write", relative, other, &response)),
        }
    }

    /// A conditional `DELETE` of the whole record set.
    async fn delete_record(&self, relative: &str, etag: &str) -> Result<DeleteOutcome, String> {
        let url = format!(
            "{}/TXT/{}?api-version={}",
            self.base, relative, self.api_version
        );
        let (status, _etag, body) = self.arm_request(Method::DELETE, &url, Some(etag), false, None).await?;
        match status {
            StatusCode::NO_CONTENT | StatusCode::OK | StatusCode::NOT_FOUND => Ok(DeleteOutcome::Gone),
            StatusCode::PRECONDITION_FAILED => Ok(DeleteOutcome::Conflict),
            other => Err(self.arm_error("delete", relative, other, &body)),
        }
    }

    /// One ARM call with a minted token: a `401` invalidates the cache and
    /// retries once — a rejected token is fixed by a fresh one, not by
    /// repeating the same.
    async fn arm_request(
        &self,
        method: Method,
        url: &str,
        if_match: Option<&str>,
        if_none_match_star: bool,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Option<String>, Value), String> {
        let token = self.tokens.management_token().await?;
        let (status, etag, response) =
            self.raw_request(method.clone(), url, &token, if_match, if_none_match_star, body)
                .await?;
        if status == StatusCode::UNAUTHORIZED {
            self.tokens.invalidate().await;
            let token = self.tokens.management_token().await?;
            return self
                .raw_request(method, url, &token, if_match, if_none_match_star, body)
                .await;
        }
        Ok((status, etag, response))
    }

    /// One request to the management plane, no token policy of its own.
    async fn raw_request(
        &self,
        method: Method,
        url: &str,
        token: &str,
        if_match: Option<&str>,
        if_none_match_star: bool,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Option<String>, Value), String> {
        let url = Url::parse(url).map_err(|error| format!("ARM URL: {error}"))?;
        let endpoint = Endpoint::from_url(&url).map_err(|error| format!("outbound: {error}"))?;
        let mut connection = self
            .outbound
            .connect(&endpoint, &self.tls)
            .await
            .map_err(|error| format!("connecting to Azure: {error}"))?;

        let mut builder = Request::builder()
            .method(method)
            .uri(connection.request_target(&url))
            .header(hyper::header::HOST, endpoint.authority())
            .header(hyper::header::USER_AGENT, "acme-proxy")
            .header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(etag) = if_match {
            builder = builder.header(hyper::header::IF_MATCH, etag);
        }
        if if_none_match_star {
            builder = builder.header(hyper::header::IF_NONE_MATCH, "*");
        }
        let bytes = body.map(Value::to_string).unwrap_or_default();
        if !bytes.is_empty() {
            builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
        }
        let request = builder
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|error| format!("building the ARM request: {error}"))?;

        let response = tokio::time::timeout(self.timeout, connection.send_request(request))
            .await
            .map_err(|_| "the Azure DNS API timed out".to_string())?
            .map_err(|error| format!("the Azure DNS API dropped the connection: {error}"))?;

        let status = response.status();
        let etag = response
            .headers()
            .get(hyper::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| format!("reading the Azure DNS API's answer: {error}"))?
            .to_bytes();
        let body = if body.is_empty() {
            Value::Null
        } else {
            match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => json!({ "error": http_client::error_excerpt(&body) }),
            }
        };
        Ok((status, etag, body))
    }

    /// The words a failed ARM call gets, with the service's own error text.
    fn arm_error(&self, verb: &str, relative: &str, status: StatusCode, body: &Value) -> String {
        let detail = body
            .get("error")
            .and_then(|error| error.get("message").or_else(|| error.get("code")))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| body.to_string());
        format!(
            "Azure DNS {verb} of {}/{} failed with {status}: {detail}",
            self.zone, relative
        )
    }
}

/// Adds `value` as its own record unless an equivalent one is already present.
/// Returns whether anything changed.
fn merge_txt_records(records: &mut Vec<Value>, value: &str) -> bool {
    if records.iter().any(|record| record_carries(record, value)) {
        return false;
    }
    records.push(json!({ "value": [value] }));
    true
}

/// Removes every record carrying `value`. Returns whether anything changed.
fn remove_txt_records(records: &mut Vec<Value>, value: &str) -> bool {
    let before = records.len();
    records.retain(|record| !record_carries(record, value));
    records.len() != before
}

/// Whether one `TXTRecords` element carries `value` in its string array.
fn record_carries(record: &Value, value: &str) -> bool {
    record
        .get("value")
        .and_then(Value::as_array)
        .map(|strings| strings.iter().any(|string| string.as_str() == Some(value)))
        .unwrap_or(false)
}

#[async_trait]
impl DnsUpdater for AzureDnsUpdater {
    async fn upsert_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let relative = self.relative_name(name)?;
        let lock = self.name_lock(&relative);
        let _guard = lock.lock().await;
        self.upsert(&relative, value).await
    }

    async fn delete_txt(&self, name: &str, value: &str) -> Result<(), String> {
        let relative = self.relative_name(name)?;
        let lock = self.name_lock(&relative);
        let _guard = lock.lock().await;
        self.delete(&relative, value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A loopback HTTP/1.1 server: one connection per request, each answered
    /// from a scripted queue. The client opens a fresh connection per
    /// request, which is what makes the queue a faithful stand-in.
    struct HttpStub {
        port: u16,
        /// (method, target, head, body) in the order received.
        requests: Arc<std::sync::Mutex<Vec<(String, String, String, String)>>>,
        responses: Arc<std::sync::Mutex<VecDeque<(u16, String)>>>,
    }

    impl HttpStub {
        async fn spawn() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            let responses = Arc::new(std::sync::Mutex::new(VecDeque::new()));
            let seen = requests.clone();
            let queued = responses.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let seen = seen.clone();
                    let queued = queued.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};

                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while stream.read_exact(&mut byte).await.is_ok() {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        let head = String::from_utf8_lossy(&head).into_owned();
                        let mut parts = head.split_whitespace();
                        let method = parts.next().unwrap_or_default().to_string();
                        let target = parts.next().unwrap_or_default().to_string();
                        let content_length = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                            })
                            .flatten()
                            .unwrap_or(0);
                        let mut body = vec![0u8; content_length];
                        let _ = stream.read_exact(&mut body).await;
                        let body = String::from_utf8_lossy(&body).into_owned();
                        seen.lock().unwrap().push((method, target, head, body));

                        let (status, response) = queued
                            .lock()
                            .unwrap()
                            .pop_front()
                            .unwrap_or((599, String::new()));
                        let response = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                            response.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                port,
                requests,
                responses,
            }
        }

        fn queue(&self, status: u16, body: &str) {
            self.responses.lock().unwrap().push_back((status, body.to_string()));
        }

        fn requests(&self) -> Vec<(String, String, String, String)> {
            self.requests.lock().unwrap().clone()
        }

        fn url(&self, path: &str) -> Url {
            Url::parse(&format!("http://127.0.0.1:{}{path}", self.port)).unwrap()
        }
    }

    /// The value of `name` in a request head.
    fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }

    /// A resolver that is never asked: every test target is a literal
    /// `127.0.0.1`, which the dial path short-circuits before a lookup.
    struct NoopResolver;

    #[async_trait::async_trait]
    impl acme_proxy_net::dns::Resolver for NoopResolver {
        async fn reverse(&self, _ip: std::net::IpAddr) -> Result<Vec<String>, String> {
            unreachable!()
        }
        async fn forward(&self, _name: &str) -> Result<Vec<std::net::IpAddr>, String> {
            unreachable!()
        }
        async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
            unreachable!()
        }
    }

    fn outbound() -> Outbound {
        acme_proxy_net::testutil::outbound_with(Arc::new(NoopResolver))
    }

    /// A token source whose two endpoints are loopback stubs.
    fn token_source(issuer: &HttpStub, entra: &HttpStub) -> Arc<FederatedTokenSource> {
        Arc::new(FederatedTokenSource {
            issuer: issuer.url("/realms/snohome"),
            entra: entra.url("/tenant/oauth2/v2.0/token"),
            client_id: "cid".to_string(),
            client_secret: "secret".to_string(),
            entra_client_id: "entra-app".to_string(),
            issuer_tls: Arc::new(http_client::webpki_tls_config()),
            public_tls: Arc::new(http_client::webpki_tls_config()),
            outbound: outbound(),
            timeout: Duration::from_secs(5),
            cached: Mutex::new(None),
        })
    }

    /// An updater whose management plane is a loopback stub.
    fn updater(base: &HttpStub, tokens: Arc<FederatedTokenSource>) -> AzureDnsUpdater {
        AzureDnsUpdater {
            zone: "example.org".to_string(),
            base: format!(
                "http://127.0.0.1:{}/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.org",
                base.port
            ),
            api_version: "2023-07-01-preview".to_string(),
            tokens,
            tls: Arc::new(http_client::webpki_tls_config()),
            outbound: outbound(),
            timeout: Duration::from_secs(5),
            locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The two stubs and the canned token answers an updater test needs.
    async fn minting_stub() -> (HttpStub, HttpStub) {
        let issuer = HttpStub::spawn().await;
        let entra = HttpStub::spawn().await;
        issuer.queue(200, r#"{"access_token":"jwt-1","expires_in":300}"#);
        entra.queue(200, r#"{"access_token":"tok-1","expires_in":3599}"#);
        (issuer, entra)
    }

    // --- the token source -------------------------------------------------

    /// The whole two-hop exchange, and that the result is cached: the second
    /// call within the window costs no request at all.
    #[tokio::test]
    async fn a_minted_token_is_cached_until_close_to_expiry() {
        let (issuer, entra) = minting_stub().await;
        let source = token_source(&issuer, &entra);

        let first = source.management_token().await.unwrap();
        assert_eq!(first, "tok-1");

        let issuer_requests = issuer.requests();
        assert_eq!(issuer_requests.len(), 1, "one mint at the issuer");
        let (method, target, head, body) = &issuer_requests[0];
        assert_eq!(method, "POST");
        assert_eq!(target, "/realms/snohome/protocol/openid-connect/token");
        let expected_credential = format!("Basic {}", BASE64_STANDARD.encode("cid:secret"));
        assert_eq!(header(head, "Authorization"), Some(expected_credential.as_str()));
        assert_eq!(body, "grant_type=client_credentials");

        let entra_requests = entra.requests();
        assert_eq!(entra_requests.len(), 1, "one exchange at Entra");
        let (_, target, head, body) = &entra_requests[0];
        assert_eq!(target, "/tenant/oauth2/v2.0/token");
        assert!(header(head, "Authorization").is_none(), "no credential on the Entra leg");
        assert!(body.contains("client_assertion=jwt-1"), "{body}");
        assert!(body.contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"), "{body}");
        assert!(body.contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default"), "{body}");
        assert!(body.contains("client_id=entra-app"), "{body}");

        let second = source.management_token().await.unwrap();
        assert_eq!(second, "tok-1");
        assert_eq!(issuer.requests().len(), 1, "the cache served the second call");
        assert_eq!(entra.requests().len(), 1, "the cache served the second call");
    }

    /// A cache entry past its refresh window is re-minted, not served.
    #[tokio::test]
    async fn an_expired_cache_is_reminted() {
        let (issuer, entra) = minting_stub().await;
        let source = token_source(&issuer, &entra);
        *source.cached.lock().await = Some((
            "stale".to_string(),
            Instant::now() - TOKEN_REFRESH_AFTER - Duration::from_secs(1),
        ));

        let token = source.management_token().await.unwrap();
        assert_eq!(token, "tok-1", "the stale entry was not served");
        assert_eq!(issuer.requests().len(), 1);
        assert_eq!(entra.requests().len(), 1);
    }

    /// A refused exchange is reported with the server's own error text.
    #[tokio::test]
    async fn a_refused_exchange_reports_the_servers_error() {
        let issuer = HttpStub::spawn().await;
        let entra = HttpStub::spawn().await;
        issuer.queue(
            401,
            r#"{"error":"invalid_client","error_description":"the client's secret is wrong"}"#,
        );
        let source = token_source(&issuer, &entra);

        let error = source.management_token().await.unwrap_err();
        assert!(error.contains("the issuer"), "{error}");
        assert!(error.contains("the client's secret is wrong"), "{error}");
        assert_eq!(entra.requests().is_empty(), true, "no Entra leg after a refused mint");
    }

    /// Entra's refusal text is the one that names the federation problem.
    #[tokio::test]
    async fn an_entra_refusal_carries_its_error_text() {
        let issuer = HttpStub::spawn().await;
        let entra = HttpStub::spawn().await;
        issuer.queue(200, r#"{"access_token":"jwt-1"}"#);
        entra.queue(
            400,
            r#"{"error":"invalid_grant","error_description":"AADSTS700021: the federated credential is not registered"}"#,
        );
        let source = token_source(&issuer, &entra);

        let error = source.management_token().await.unwrap_err();
        assert!(error.contains("Entra"), "{error}");
        assert!(error.contains("AADSTS700021"), "{error}");
    }

    // --- configuration -----------------------------------------------------

    fn azure_config() -> AzureDnsConfig {
        AzureDnsConfig {
            zone: "example.org.".to_string(),
            subscription_id: "sub".to_string(),
            resource_group: "rg".to_string(),
            api_version: "2023-07-01-preview".to_string(),
            issuer: "https://sso.example.org/realms/snohome".to_string(),
            client_id: "cid".to_string(),
            client_secret: "secret".to_string(),
            issuer_ca_file: String::new(),
            entra_tenant_id: "tenant".to_string(),
            entra_client_id: "entra-app".to_string(),
        }
    }

    /// A resolver that resolves nothing: `from_config` makes no network
    /// call, so the egress it receives is never exercised.
    struct Never;

    #[async_trait::async_trait]
    impl acme_proxy_net::dns::Resolver for Never {
        async fn reverse(&self, _ip: std::net::IpAddr) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
        async fn forward(&self, _name: &str) -> Result<Vec<std::net::IpAddr>, String> {
            Ok(Vec::new())
        }
        async fn txt(&self, _name: &str) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
    }

    fn never_egress() -> Arc<acme_proxy_net::egress::Egress> {
        acme_proxy_net::testutil::egress_with(Arc::new(Never))
    }

    /// Each unset field is a startup error naming itself, the same rule the
    /// rfc2136 provider holds: a credential that cannot work will never start
    /// working on its own.
    #[test]
    fn every_unset_field_is_a_startup_error() {
        let egress = never_egress();
        let valid_source = Arc::new(
            FederatedTokenSource::from_config(&azure_config(), &egress).unwrap(),
        );

        let fields = [
            "zone",
            "subscription_id",
            "resource_group",
            "api_version",
            "issuer",
            "client_id",
            "client_secret",
            "entra_tenant_id",
            "entra_client_id",
        ];
        for field in fields {
            let mut cfg = azure_config();
            let slot = match field {
                "zone" => &mut cfg.zone,
                "subscription_id" => &mut cfg.subscription_id,
                "resource_group" => &mut cfg.resource_group,
                "api_version" => &mut cfg.api_version,
                "issuer" => &mut cfg.issuer,
                "client_id" => &mut cfg.client_id,
                "client_secret" => &mut cfg.client_secret,
                "entra_tenant_id" => &mut cfg.entra_tenant_id,
                "entra_client_id" => &mut cfg.entra_client_id,
                _ => unreachable!(),
            };
            slot.clear();

            // Each constructor validates the fields it spends; the field must
            // be caught by whichever of the two it belongs to.
            let error = FederatedTokenSource::from_config(&cfg, &egress)
                .err()
                .map(|error| error.to_string())
                .or_else(|| AzureDnsUpdater::from_config(&cfg, valid_source.clone()).err().map(|error| error.to_string()))
                .unwrap_or_else(|| panic!("{field}: this configuration must not build"));
            assert!(error.contains(field), "{field}: {error}");
        }
    }

    /// A well-formed configuration builds, and the zone is normalised the way
    /// the record paths expect: lowercased, without its trailing dot.
    #[test]
    fn a_well_formed_config_builds() {
        let egress = never_egress();

        let source = FederatedTokenSource::from_config(&azure_config(), &egress).unwrap();
        assert_eq!(source.issuer.as_str(), "https://sso.example.org/realms/snohome");
        assert_eq!(
            source.entra.as_str(),
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
        );

        let updater = AzureDnsUpdater::from_config(&azure_config(), Arc::new(source)).unwrap();
        assert_eq!(updater.zone, "example.org");
        assert_eq!(
            updater.base,
            "https://management.azure.com/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.org"
        );
    }

    /// The issuer's private roots come from a file, and a file that is not
    /// certificates is a startup error.
    #[test]
    fn a_malformed_ca_file_is_a_startup_error() {
        let egress = never_egress();

        let mut cfg = azure_config();
        cfg.issuer_ca_file = "/nonexistent/roots.pem".to_string();
        assert!(FederatedTokenSource::from_config(&cfg, &egress).is_err());

        let path = std::env::temp_dir().join("acme-proxy-azure-bad-pem.pem");
        std::fs::write(&path, "not a pem file at all").unwrap();
        cfg.issuer_ca_file = path.to_string_lossy().to_string();
        let error = FederatedTokenSource::from_config(&cfg, &egress)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("issuer_ca_file"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    /// A real PEM is parsed into its blocks.
    #[test]
    fn a_pem_file_yields_its_certificate_blocks() {
        let pem = "-----BEGIN CERTIFICATE-----\n\
MIIDJTCCAg2gAwIBAgIUSJzdDjDQ3LRfRwdTgaRIfbADlQcwDQYJKoZIhvcNAQEL\n\
BQAwIjEgMB4GA1UEAwwXVGVzdCBDQSBmb3IgUEVNIHBhcnNpbmcwHhcNMjYxMDA0\n\
MDkzNzMwWhcNMzYxMDAxMDkzNzMwWjAiMSAwHgYDVQQDDBdUZXN0IENBIGZvciBQ\n\
RU0gcGFyc2luZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMERXLdr\n\
X9wnUOU1xRxi9ns+HrxSV42E1icYoQ/yOxbtqMRva87jjVTzVUNoFvJis/9/pTt1\n\
IvyWRWwbYIEm4mvNtqbNiG61K2kHOkjVub4JJMx84RUtznv4RmWX9XrMw9CsxANQ\n\
OVp7Jy9Ys964tHvqWc/p6Q96gjR3rZly2STbaa+NI4zwplwm8flgJCAQ6qnueufS\n\
rpJ9NiRGphmFaX/Dx3Ly3Tg+5nm9ELSC9q374mmA1DQEjlmHMx4anRLitzDyPcb6\n\
EAuA1p5beUISZ2FBt0mic/esaavi0BF237ssEr4fNpb7WwJE4FF5mNrnbOQkeRWr\n\
f0dEq4rZaO1k7ZUCAwEAAaNTMFEwHQYDVR0OBBYEFEyEKcgNvdMjTQo9R75jXAx/\n\
rLk8MB8GA1UdIwQYMBaAFEyEKcgNvdMjTQo9R75jXAx/rLk8MA8GA1UdEwEB/wQF\n\
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBACWrzu0CkAekoAibyI8Q8MhMT4Yk6CHL\n\
zL/F9f5epvfdu6e1/QO4rjGtFP2uaJf8MHiGs8n6lKbHeVqyUOqdql/5FuTfKu1G\n\
DND2fDruaH+z9TQXmc9i1Yml/lyyZ6W0lCdGKntglhP3/l+nLL57UzJ6FUtle3+H\n\
iAS5jZzlfB2pKhKsdeBfzvTPkaG/Ddnj4ECpRIM6VLk9EKmBDlOXKH0Avdpt3QSS\n\
uTa7lGeY/eppPRgYC9APhJfXq9hNc9955Pw9ZX3YAau1Vv97CiTjKfeyM+c0ndMR\n\
HVWFQCe7u/AXvnGUSbHIosmUYq2dLSCH4N6IofOyRptmgYwFT3XRIe8=\n\
-----END CERTIFICATE-----\n";
        let certs = pem_certs(pem).unwrap();
        assert_eq!(certs.len(), 1);
    }

    // --- names -------------------------------------------------------------

    /// The apex is `@`, a subdomain its bare label run, and anything else is
    /// outside the zone.
    #[test]
    fn names_map_into_the_zones_own_terms() {
        let egress = never_egress();
        let source = FederatedTokenSource::from_config(&azure_config(), &egress).unwrap();
        let updater = AzureDnsUpdater::from_config(&azure_config(), Arc::new(source)).unwrap();

        assert_eq!(updater.relative_name("example.org.").unwrap(), "@");
        assert_eq!(
            updater.relative_name("_acme-challenge.example.org.").unwrap(),
            "_acme-challenge"
        );
        assert_eq!(
            updater.relative_name("_acme-challenge.www.example.org.").unwrap(),
            "_acme-challenge.www"
        );
        assert_eq!(
            updater.relative_name("_ACME-CHALLENGE.Example.ORG.").unwrap(),
            "_acme-challenge"
        );
        let error = updater
            .relative_name("_acme-challenge.example.net.")
            .unwrap_err();
        assert!(error.contains("outside the zone"), "{error}");
        // A name that merely contains the zone is not in it.
        let error = updater.relative_name("notexample.org.").unwrap_err();
        assert!(error.contains("outside the zone"), "{error}");
    }

    // --- the record-set algebra ---------------------------------------------

    /// The additive/retactive pair: a duplicate is a no-op, two values
    /// coexist, and a retraction removes only its own value.
    #[test]
    fn merge_and_remove_keep_other_values() {
        let mut records = vec![json!({ "value": ["a"] })];

        assert!(merge_txt_records(&mut records, "b"), "a new value is added");
        assert_eq!(records.len(), 2);
        assert!(!merge_txt_records(&mut records, "b"), "a duplicate is a no-op");
        assert_eq!(records.len(), 2);

        assert!(remove_txt_records(&mut records, "a"), "the retracted value goes");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], json!({ "value": ["b"] }));
        assert!(!remove_txt_records(&mut records, "a"), "a second retraction is a no-op");
        assert!(remove_txt_records(&mut records, "b"), "the last value empties the set");
        assert!(records.is_empty());
    }

    // --- the updater against the stub ----------------------------------------

    /// A create: `404` on the read, `If-None-Match: *` on the write, and the
    /// token the exchange minted on the `Authorization` header.
    #[tokio::test]
    async fn a_create_puts_with_if_none_match_star() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(404, "");
        base.queue(201, r#"{"etag":"e1"}"#);
        let updater = updater(&base, token_source(&issuer, &entra));

        updater
            .upsert_txt("_acme-challenge.example.org.", "digest")
            .await
            .unwrap();

        let requests = base.requests();
        assert_eq!(requests.len(), 2, "one read, one write");
        let (method, target, head, _) = &requests[0];
        assert_eq!(method, "GET");
        assert_eq!(target, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/dnszones/example.org/TXT/_acme-challenge?api-version=2023-07-01-preview");
        assert_eq!(header(head, "Authorization"), Some("Bearer tok-1"));
        assert!(header(head, "If-Match").is_none());

        let (method, _target, head, body) = &requests[1];
        assert_eq!(method, "PUT");
        assert_eq!(header(head, "If-None-Match"), Some("*"));
        assert!(header(head, "If-Match").is_none());
        assert!(body.contains(r#""TTL":60"#), "{body}");
        assert!(body.contains(r#""value":["digest"]"#), "{body}");
    }

    /// A value that is already published costs no write at all.
    #[tokio::test]
    async fn a_value_already_published_is_not_written_again() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(
            200,
            r#"{"etag":"e1","properties":{"TTL":60,"TXTRecords":[{"value":["digest"]}]}}"#,
        );
        let updater = updater(&base, token_source(&issuer, &entra));

        updater
            .upsert_txt("_acme-challenge.example.org.", "digest")
            .await
            .unwrap();

        assert_eq!(base.requests().len(), 1, "the read is the whole of it");
    }

    /// A second value at the same name is merged in with `If-Match`, and the
    /// record set's own TTL is preserved, not overwritten.
    #[tokio::test]
    async fn a_second_value_is_merged_with_if_match() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(
            200,
            r#"{"etag":"e1","properties":{"TTL":300,"TXTRecords":[{"value":["a"]}]}}"#,
        );
        base.queue(200, r#"{"etag":"e2"}"#);
        let updater = updater(&base, token_source(&issuer, &entra));

        updater.upsert_txt("_acme-challenge.example.org.", "b").await.unwrap();

        let requests = base.requests();
        assert_eq!(requests.len(), 2);
        let (method, _target, head, body) = &requests[1];
        assert_eq!(method, "PUT");
        assert_eq!(header(head, "If-Match"), Some("e1"));
        assert!(body.contains(r#""TTL":300"#), "the existing TTL is kept: {body}");
        assert!(body.contains(r#""value":["a"]"#), "{body}");
        assert!(body.contains(r#""value":["b"]"#), "{body}");
    }

    /// A `412` on the write means the world moved: re-read, re-apply, and the
    /// second attempt lands.
    #[tokio::test]
    async fn a_conflict_is_reread_and_retried() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(404, "");
        base.queue(412, r#"{"error":{"code":"RecordSetConflict","message":"the etag moved"}}"#);
        base.queue(
            200,
            r#"{"etag":"e1","properties":{"TTL":60,"TXTRecords":[{"value":["other"]}]}}"#,
        );
        base.queue(200, r#"{"etag":"e2"}"#);
        let updater = updater(&base, token_source(&issuer, &entra));

        updater.upsert_txt("_acme-challenge.example.org.", "mine").await.unwrap();

        let requests = base.requests();
        assert_eq!(requests.len(), 4, "read, conflict, re-read, write");
        assert_eq!(requests[0].0, "GET");
        assert_eq!(requests[1].0, "PUT");
        assert_eq!(requests[2].0, "GET");
        assert_eq!(requests[3].0, "PUT");
        assert_eq!(header(&requests[3].2, "If-Match"), Some("e1"));
        assert!(requests[3].3.contains(r#""value":["other"]"#));
        assert!(requests[3].3.contains(r#""value":["mine"]"#));
    }

    /// Conflicts that never resolve are given up on, with the count in the
    /// error.
    #[tokio::test]
    async fn repeated_conflicts_are_given_up_on() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        for _ in 0..MAX_CONFLICT_ATTEMPTS {
            base.queue(404, "");
            base.queue(412, "");
        }
        let updater = updater(&base, token_source(&issuer, &entra));

        let error = updater
            .upsert_txt("_acme-challenge.example.org.", "mine")
            .await
            .unwrap_err();
        assert!(error.contains("giving up"), "{error}");
        assert!(error.contains(&MAX_CONFLICT_ATTEMPTS.to_string()), "{error}");
    }

    /// A retraction of one of several values rewrites the record set without
    /// it, leaving the others.
    #[tokio::test]
    async fn a_retraction_puts_the_reduced_array() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(
            200,
            r#"{"etag":"e1","properties":{"TTL":60,"TXTRecords":[{"value":["a"]},{"value":["b"]}]}}"#,
        );
        base.queue(200, r#"{"etag":"e2"}"#);
        let updater = updater(&base, token_source(&issuer, &entra));

        updater.delete_txt("_acme-challenge.example.org.", "a").await.unwrap();

        let requests = base.requests();
        assert_eq!(requests.len(), 2);
        let (method, _target, head, body) = &requests[1];
        assert_eq!(method, "PUT");
        assert_eq!(header(head, "If-Match"), Some("e1"));
        assert!(!body.contains(r#""value":["a"]"#), "{body}");
        assert!(body.contains(r#""value":["b"]"#), "{body}");
    }

    /// A retraction of the last value deletes the record set itself.
    #[tokio::test]
    async fn a_retraction_of_the_last_value_deletes_the_record() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(
            200,
            r#"{"etag":"e1","properties":{"TTL":60,"TXTRecords":[{"value":["a"]}]}}"#,
        );
        base.queue(204, "");
        let updater = updater(&base, token_source(&issuer, &entra));

        updater.delete_txt("_acme-challenge.example.org.", "a").await.unwrap();

        let requests = base.requests();
        assert_eq!(requests.len(), 2);
        let (method, _target, head, _) = &requests[1];
        assert_eq!(method, "DELETE");
        assert_eq!(header(head, "If-Match"), Some("e1"));
    }

    /// Retracting a value that is not there is not an error: the read says so,
    /// and nothing is written.
    #[tokio::test]
    async fn a_retraction_of_an_absent_value_is_a_noop() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(404, "");
        let updater = updater(&base, token_source(&issuer, &entra));

        updater
            .delete_txt("_acme-challenge.example.org.", "a")
            .await
            .unwrap();
        assert_eq!(base.requests().len(), 1);
    }

    /// A `401` from ARM means the token was rejected: it is invalidated, a
    /// fresh one minted, and the call retried with it.
    #[tokio::test]
    async fn a_401_invalidates_the_token_and_retries() {
        let issuer = HttpStub::spawn().await;
        let entra = HttpStub::spawn().await;
        issuer.queue(200, r#"{"access_token":"jwt-1"}"#);
        entra.queue(200, r#"{"access_token":"tok-1"}"#);
        issuer.queue(200, r#"{"access_token":"jwt-2"}"#);
        entra.queue(200, r#"{"access_token":"tok-2"}"#);
        let base = HttpStub::spawn().await;
        base.queue(401, r#"{"error":{"message":"the token was rejected"}}"#);
        base.queue(
            200,
            r#"{"etag":"e1","properties":{"TTL":60,"TXTRecords":[{"value":["a"]}]}}"#,
        );
        let updater = updater(&base, token_source(&issuer, &entra));

        updater
            .upsert_txt("_acme-challenge.example.org.", "a")
            .await
            .unwrap();

        let requests = base.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(header(&requests[0].2, "Authorization"), Some("Bearer tok-1"));
        assert_eq!(header(&requests[1].2, "Authorization"), Some("Bearer tok-2"));
        assert_eq!(issuer.requests().len(), 2, "one mint per token");
        assert_eq!(entra.requests().len(), 2, "one exchange per token");
    }

    /// A failure that is not a conflict is reported with the service's own
    /// error text.
    #[tokio::test]
    async fn a_failed_write_reports_the_services_error() {
        let (issuer, entra) = minting_stub().await;
        let base = HttpStub::spawn().await;
        base.queue(404, "");
        base.queue(
            409,
            r#"{"error":{"code":"RecordSetConflict","message":"the record set is locked"}}"#,
        );
        let updater = updater(&base, token_source(&issuer, &entra));

        let error = updater
            .upsert_txt("_acme-challenge.example.org.", "mine")
            .await
            .unwrap_err();
        assert!(error.contains("409"), "{error}");
        assert!(error.contains("the record set is locked"), "{error}");
    }
}
