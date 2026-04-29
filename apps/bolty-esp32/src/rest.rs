use core::fmt::Write as _;
use std::sync::{Arc, Mutex};

use bolty_core::{
    commands::Command,
    config::{BoltyConfig, LnurlString},
    secret::{AesKey, CardKeys},
    service::{BoltyService, ServiceStatus, WorkflowResult},
    workflow::dispatch_command,
};
use embedded_svc::{
    http::{Headers, Method},
    io::{Read, Write},
};
use esp_idf_hal::io::EspIOError;
use esp_idf_svc::http::server::{
    Configuration as HttpConfig, EspHttpConnection, EspHttpServer, Request,
};
use esp_idf_sys::EspError;
use heapless::String;

pub type SharedConfig = Arc<Mutex<BoltyConfig>>;
pub type SharedService<S> = Arc<Mutex<S>>;

const MAX_BODY_LEN: usize = 512;
const JSON_CONTENT_TYPE: (&str, &str) = ("Content-Type", "application/json");

pub trait RestBoltyService: BoltyService {
    fn sync_from(&mut self, config: &BoltyConfig);
}

pub struct RestServer<S>
where
    S: RestBoltyService + Send + 'static,
{
    server: EspHttpServer<'static>,
    _config: SharedConfig,
    _service: SharedService<S>,
}

impl<S> RestServer<S>
where
    S: RestBoltyService + Send + 'static,
{
    pub fn start(
        port: u16,
        config: SharedConfig,
        service: SharedService<S>,
    ) -> Result<Self, EspError> {
        let mut server = EspHttpServer::new(&HttpConfig {
            http_port: port,
            stack_size: 8192,
            ..Default::default()
        })
        .map_err(|error| error.0)?;

        {
            let config = Arc::clone(&config);
            let service = Arc::clone(&service);
            server.fn_handler("/api/status", Method::Get, move |request| {
                handle_status(request, &config, &service)
            })?;
        }

        {
            let config = Arc::clone(&config);
            let service = Arc::clone(&service);
            server.fn_handler("/api/uid", Method::Get, move |request| {
                handle_uid(request, &config, &service)
            })?;
        }

        {
            let config = Arc::clone(&config);
            let service = Arc::clone(&service);
            server.fn_handler("/api/check", Method::Get, move |request| {
                handle_check(request, &config, &service)
            })?;
        }

        {
            let config = Arc::clone(&config);
            let service = Arc::clone(&service);
            server.fn_handler("/api/keys", Method::Post, move |request| {
                handle_keys(request, &config, &service)
            })?;
        }

        {
            let config = Arc::clone(&config);
            let service = Arc::clone(&service);
            server.fn_handler("/api/url", Method::Post, move |request| {
                handle_url(request, &config, &service)
            })?;
        }

        {
            let config = Arc::clone(&config);
            let service = Arc::clone(&service);
            server.fn_handler("/api/burn", Method::Post, move |request| {
                handle_action(request, &config, &service, Command::Burn)
            })?;
        }

        {
            let config = Arc::clone(&config);
            let service = Arc::clone(&service);
            server.fn_handler("/api/wipe", Method::Post, move |request| {
                handle_action(request, &config, &service, Command::Wipe)
            })?;
        }

        Ok(Self {
            server,
            _config: config,
            _service: service,
        })
    }

    pub fn stop(self) {
        drop(self);
    }
}

fn handle_status<S>(
    request: Request<&mut EspHttpConnection<'_>>,
    config: &SharedConfig,
    service: &SharedService<S>,
) -> Result<(), EspIOError>
where
    S: RestBoltyService + Send + 'static,
{
    if !is_authorized(&request, config, TokenScope::Read) {
        return respond_json(request, 401, json_err("unauthorized").as_str());
    }

    let status = match service.lock() {
        Ok(service) => service.get_status(),
        Err(_) => return respond_json(request, 500, json_err("service unavailable").as_str()),
    };

    let body = json_status(&status);
    respond_json(request, 200, body.as_str())
}

fn handle_uid<S>(
    request: Request<&mut EspHttpConnection<'_>>,
    config: &SharedConfig,
    service: &SharedService<S>,
) -> Result<(), EspIOError>
where
    S: RestBoltyService + Send + 'static,
{
    if !is_authorized(&request, config, TokenScope::Read) {
        return respond_json(request, 401, json_err("unauthorized").as_str());
    }

    let status = match service.lock() {
        Ok(service) => service.get_status(),
        Err(_) => return respond_json(request, 500, json_err("service unavailable").as_str()),
    };

    let Some(uid) = status.last_uid else {
        return respond_json(request, 200, json_err("no uid").as_str());
    };

    let mut uid_hex = String::<32>::new();
    let _ = push_uid_hex(&mut uid_hex, &uid);

    let mut extra = String::<64>::new();
    let _ = push_json_key(&mut extra, "uid");
    let _ = push_json_string(&mut extra, uid_hex.as_str());

    let body = json_ok(extra.as_str());
    respond_json(request, 200, body.as_str())
}

fn handle_check<S>(
    request: Request<&mut EspHttpConnection<'_>>,
    config: &SharedConfig,
    service: &SharedService<S>,
) -> Result<(), EspIOError>
where
    S: RestBoltyService + Send + 'static,
{
    if !is_authorized(&request, config, TokenScope::Read) {
        return respond_json(request, 401, json_err("unauthorized").as_str());
    }

    let result = with_state(config, service, |config, service| {
        let result = dispatch_command(Command::Check, service, config);
        service.sync_from(config);
        result
    });

    match result {
        Ok(WorkflowResult::Success) => respond_json(request, 200, json_ok("\"blank\":true").as_str()),
        Ok(WorkflowResult::Error(message)) if message.as_str() == "card not blank" => {
            respond_json(request, 200, json_ok("\"blank\":false").as_str())
        }
        Ok(other) => respond_json(request, 200, json_err(workflow_error_message(&other)).as_str()),
        Err(message) => respond_json(request, 500, json_err(message).as_str()),
    }
}

fn handle_keys<S>(
    mut request: Request<&mut EspHttpConnection<'_>>,
    config: &SharedConfig,
    service: &SharedService<S>,
) -> Result<(), EspIOError>
where
    S: RestBoltyService + Send + 'static,
{
    if !is_authorized(&request, config, TokenScope::Write) {
        return respond_json(request, 401, json_err("unauthorized").as_str());
    }

    let body = match read_body(&mut request) {
        Ok(body) => body,
        Err(ReadBodyError::TooLarge) => {
            return respond_json(request, 413, json_err("request too large").as_str())
        }
        Err(ReadBodyError::InvalidUtf8) => {
            return respond_json(request, 400, json_err("invalid utf-8 body").as_str())
        }
        Err(ReadBodyError::Io(error)) => return Err(error),
    };

    let keys = match parse_card_keys(body.as_str()) {
        Ok(keys) => keys,
        Err(message) => return respond_json(request, 400, json_err(message).as_str()),
    };

    let result = with_state(config, service, move |config, service| {
        let result = dispatch_command(Command::SetKeys(keys), service, config);
        service.sync_from(config);
        result
    });

    match result {
        Ok(WorkflowResult::Success) => respond_json(request, 200, json_ok("").as_str()),
        Ok(other) => respond_json(request, 200, json_err(workflow_error_message(&other)).as_str()),
        Err(message) => respond_json(request, 500, json_err(message).as_str()),
    }
}

fn handle_url<S>(
    mut request: Request<&mut EspHttpConnection<'_>>,
    config: &SharedConfig,
    service: &SharedService<S>,
) -> Result<(), EspIOError>
where
    S: RestBoltyService + Send + 'static,
{
    if !is_authorized(&request, config, TokenScope::Write) {
        return respond_json(request, 401, json_err("unauthorized").as_str());
    }

    let body = match read_body(&mut request) {
        Ok(body) => body,
        Err(ReadBodyError::TooLarge) => {
            return respond_json(request, 413, json_err("request too large").as_str())
        }
        Err(ReadBodyError::InvalidUtf8) => {
            return respond_json(request, 400, json_err("invalid utf-8 body").as_str())
        }
        Err(ReadBodyError::Io(error)) => return Err(error),
    };

    let url = match extract_json_string(body.as_str(), "url") {
        Some(url) => {
            let mut out = LnurlString::new();
            if out.push_str(url).is_err() {
                return respond_json(request, 400, json_err("url too long").as_str());
            }
            out
        }
        None => return respond_json(request, 400, json_err("missing url").as_str()),
    };

    let result = with_state(config, service, move |config, service| {
        let result = dispatch_command(Command::SetUrl(url), service, config);
        service.sync_from(config);
        result
    });

    match result {
        Ok(WorkflowResult::Success) => respond_json(request, 200, json_ok("").as_str()),
        Ok(other) => respond_json(request, 200, json_err(workflow_error_message(&other)).as_str()),
        Err(message) => respond_json(request, 500, json_err(message).as_str()),
    }
}

fn handle_action<S>(
    request: Request<&mut EspHttpConnection<'_>>,
    config: &SharedConfig,
    service: &SharedService<S>,
    command: Command,
) -> Result<(), EspIOError>
where
    S: RestBoltyService + Send + 'static,
{
    if !is_authorized(&request, config, TokenScope::Write) {
        return respond_json(request, 401, json_err("unauthorized").as_str());
    }

    let result = with_state(config, service, move |config, service| {
        let result = dispatch_command(command, service, config);
        service.sync_from(config);
        result
    });

    match result {
        Ok(WorkflowResult::Success) => {
            respond_json(request, 200, json_ok("\"status\":\"done\"").as_str())
        }
        Ok(_) => respond_json(request, 200, "{\"ok\":false,\"status\":\"error\"}"),
        Err(_) => respond_json(request, 500, "{\"ok\":false,\"status\":\"error\"}"),
    }
}

fn respond_json(
    request: Request<&mut EspHttpConnection<'_>>,
    status: u16,
    body: &str,
) -> Result<(), EspIOError> {
    request
        .into_response(status, Some(status_message(status)), &[JSON_CONTENT_TYPE])?
        .write_all(body.as_bytes())
}

fn status_message(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    }
}

fn json_status(status: &ServiceStatus) -> String<512> {
    let mut uid = String::<32>::new();
    if let Some(last_uid) = status.last_uid {
        let _ = push_uid_hex(&mut uid, &last_uid);
    }

    let mut extra = String::<480>::new();
    let _ = push_json_key(&mut extra, "nfc_ready");
    let _ = write!(extra, "{}", status.nfc_ready);
    extra.push(',').ok();
    let _ = push_json_key(&mut extra, "uid");
    let _ = push_json_string(&mut extra, if uid.is_empty() { "none" } else { uid.as_str() });
    extra.push(',').ok();
    let _ = push_json_key(&mut extra, "lnurl");
    let _ = push_json_string(
        &mut extra,
        status.lnurl.as_ref().map(LnurlString::as_str).unwrap_or("none"),
    );

    json_ok(extra.as_str())
}

pub fn json_ok(extra: &str) -> String<512> {
    let mut out = String::<512>::new();
    out.push_str("{\"ok\":true").ok();
    if !extra.is_empty() {
        out.push(',').ok();
        out.push_str(extra).ok();
    }
    out.push('}').ok();
    out
}

pub fn json_err(msg: &str) -> String<256> {
    let mut out = String::<256>::new();
    out.push_str("{\"ok\":false,\"error\":\"").ok();
    let _ = push_escaped_json(&mut out, msg);
    out.push_str("\"}").ok();
    out
}

fn push_uid_hex<const N: usize>(out: &mut String<N>, uid: &[u8]) -> core::fmt::Result {
    for byte in uid {
        write!(out, "{byte:02X}")?;
    }
    Ok(())
}

fn push_json_key<const N: usize>(out: &mut String<N>, key: &str) -> core::fmt::Result {
    out.push('"').map_err(|_| core::fmt::Error)?;
    push_escaped_json(out, key)?;
    out.push_str("\":").map_err(|_| core::fmt::Error)
}

fn push_json_string<const N: usize>(out: &mut String<N>, value: &str) -> core::fmt::Result {
    out.push('"').map_err(|_| core::fmt::Error)?;
    push_escaped_json(out, value)?;
    out.push('"').map_err(|_| core::fmt::Error)
}

fn push_escaped_json<const N: usize>(out: &mut String<N>, value: &str) -> core::fmt::Result {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\").map_err(|_| core::fmt::Error)?,
            '"' => out.push_str("\\\"").map_err(|_| core::fmt::Error)?,
            '\n' => out.push_str("\\n").map_err(|_| core::fmt::Error)?,
            '\r' => out.push_str("\\r").map_err(|_| core::fmt::Error)?,
            '\t' => out.push_str("\\t").map_err(|_| core::fmt::Error)?,
            other => out.push(other).map_err(|_| core::fmt::Error)?,
        }
    }
    Ok(())
}

fn with_state<S, T, F>(config: &SharedConfig, service: &SharedService<S>, f: F) -> Result<T, &'static str>
where
    S: RestBoltyService + Send + 'static,
    F: FnOnce(&mut BoltyConfig, &mut S) -> T,
{
    let mut config = config.lock().map_err(|_| "config unavailable")?;
    let mut service = service.lock().map_err(|_| "service unavailable")?;
    Ok(f(&mut config, &mut service))
}

fn workflow_error_message(result: &WorkflowResult) -> &str {
    match result {
        WorkflowResult::Success => "success",
        WorkflowResult::CardNotPresent => "card not present",
        WorkflowResult::AuthFailed => "authentication failed",
        WorkflowResult::AuthDelay => "authentication delay; remove card from field, wait, and retry with the correct key",
        WorkflowResult::WipeRefused => "wipe refused",
        WorkflowResult::Error(message) => message.as_str(),
    }
}

fn parse_card_keys(body: &str) -> Result<CardKeys, &'static str> {
    let k0 = parse_key_field(body, "k0")?;
    let k1 = parse_key_field(body, "k1")?;
    let k2 = parse_key_field(body, "k2")?;
    let k3 = parse_key_field(body, "k3")?;
    let k4 = parse_key_field(body, "k4")?;

    Ok(CardKeys { k0, k1, k2, k3, k4 })
}

fn parse_key_field(body: &str, key: &str) -> Result<AesKey, &'static str> {
    let value = extract_json_string(body, key).ok_or(match key {
        "k0" => "missing k0",
        "k1" => "missing k1",
        "k2" => "missing k2",
        "k3" => "missing k3",
        "k4" => "missing k4",
        _ => "missing key field",
    })?;
    AesKey::from_hex(value).map_err(|_| "invalid hex key")
}

fn extract_json_string<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let mut pattern = String::<32>::new();
    write!(pattern, "\"{key}\"").ok()?;
    let key_start = body.find(pattern.as_str())?;
    let after_key = &body[key_start + pattern.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }

    let content = &after_colon[1..];
    let mut escaped = false;
    for (index, byte) in content.as_bytes().iter().copied().enumerate() {
        match byte {
            b'\\' if !escaped => escaped = true,
            b'"' if !escaped => return Some(&content[..index]),
            _ => escaped = false,
        }
    }

    None
}

enum ReadBodyError {
    Io(EspIOError),
    TooLarge,
    InvalidUtf8,
}

fn read_body(request: &mut Request<&mut EspHttpConnection<'_>>) -> Result<String<MAX_BODY_LEN>, ReadBodyError> {
    let Some(length) = request.content_len() else {
        return Ok(String::new());
    };

    let length = length as usize;
    if length > MAX_BODY_LEN {
        return Err(ReadBodyError::TooLarge);
    }

    let mut bytes = [0u8; MAX_BODY_LEN];
    let mut read = 0usize;
    while read < length {
        let count = request
            .read(&mut bytes[read..length])
            .map_err(ReadBodyError::Io)?;
        if count == 0 {
            break;
        }
        read += count;
    }

    let body = core::str::from_utf8(&bytes[..read]).map_err(|_| ReadBodyError::InvalidUtf8)?;
    let mut out = String::<MAX_BODY_LEN>::new();
    out.push_str(body).map_err(|_| ReadBodyError::TooLarge)?;
    Ok(out)
}

#[derive(Clone, Copy)]
enum TokenScope {
    Read,
    Write,
}

fn is_authorized(
    request: &Request<&mut EspHttpConnection<'_>>,
    config: &SharedConfig,
    scope: TokenScope,
) -> bool {
    let expected = match config.lock() {
        Ok(config) => match scope {
            TokenScope::Read => config.rest_read_token.clone(),
            TokenScope::Write => config.rest_write_token.clone(),
        },
        Err(_) => return false,
    };

    let Some(expected) = expected else {
        return true;
    };

    let Some(provided) = bearer_token(request) else {
        return false;
    };

    constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

fn bearer_token<'a>(request: &'a Request<&mut EspHttpConnection<'_>>) -> Option<&'a str> {
    let header = request.header("Authorization")?;
    if header.len() < 7 || !header[..7].eq_ignore_ascii_case("Bearer ") {
        return None;
    }
    Some(&header[7..])
}

fn constant_time_eq(expected: &[u8], provided: &[u8]) -> bool {
    let mut diff = expected.len() ^ provided.len();
    let max_len = expected.len().max(provided.len());
    for index in 0..max_len {
        let left = expected.get(index).copied().unwrap_or_default();
        let right = provided.get(index).copied().unwrap_or_default();
        diff |= usize::from(left ^ right);
    }
    diff == 0
}
