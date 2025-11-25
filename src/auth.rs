use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;
use url::form_urlencoded;
use rand::distr::Alphanumeric;
use rand::Rng;
use rand::thread_rng;


use rand::prelude::*;
use web_view::*;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug)]
pub enum AuthError {
    Http(String),
    OutdatedToken(String),
    DoesNotOwnMinecraft(String),
    InconsistentUserHash,
    Other(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::Http(s) => write!(f, "HTTP error: {}", s),
            AuthError::OutdatedToken(s) => write!(f, "Outdated token: {}", s),
            AuthError::DoesNotOwnMinecraft(s) => write!(f, "Does not own Minecraft: {}", s),
            AuthError::InconsistentUserHash => write!(f, "Inconsistent user hash"),
            AuthError::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for AuthError {}

pub struct MicrosoftAuthSession {
    pub access_token: String,
    pub username: String,
    pub uuid: String,
    pub client_id: String,
    pub refresh_token: String,
    pub app_id: String,
    pub redirect_uri: String,
    pub xuid: String,
    _new_username: Option<String>,
}

impl MicrosoftAuthSession {
    pub fn new() -> Self {
        Self {
            access_token: String::new(),
            username: String::new(),
            uuid: String::new(),
            client_id: String::new(),
            refresh_token: String::new(),
            app_id: String::new(),
            redirect_uri: String::new(),
            xuid: String::new(),
            _new_username: None,
        }
    }

    /// Generate random string for nonce/state
    pub fn random_string(len: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }


    /// Build Microsoft OAuth URL
    pub fn get_authentication_url(
        client_id: &str,
        redirect_uri: &str,
        email: &str,
    ) -> (String, String, String) {
        let nonce = Self::random_string(16);
        let state = Self::random_string(16);

        let params = [
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "xboxlive.signin offline_access openid email profile"),
            ("login_hint", email),
            ("nonce", &nonce),
            ("state", &state),
            ("prompt", "login"),
            ("response_mode", "form_post"),
        ];

        let query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        (
            format!("https://login.live.com/oauth20_authorize.srf?{}", query),
            nonce,
            state,
        )
    }

    /// Open a webview to authenticate and capture the code
    pub fn authenticate_with_webview(
        email: &str,
        client_id: &str,
        redirect_port: u16,
    ) -> Result<String, AuthError> {
        let redirect_uri = format!("http://127.0.0.1:{}", redirect_port);
        let (auth_url, _nonce, _state) = Self::get_authentication_url(client_id, &redirect_uri, email);

        let code_holder = Arc::new(Mutex::new(None));
        let code_clone = Arc::clone(&code_holder);

        let listener_thread = thread::spawn(move || {
            let listener =
                TcpListener::bind(("127.0.0.1", redirect_port)).expect("Failed to bind redirect port");
            let (mut stream, _) = listener.accept().expect("Failed to accept connection");
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer);

            let request = String::from_utf8_lossy(&buffer);
            println!("--- RAW REQUEST ---\n{}\n-------------------", request);

            let code = request
                .lines()
                .last()
                .and_then(|line| {
                    form_urlencoded::parse(line.as_bytes())
                        .find(|(k, _)| k == "code")
                        .map(|(_, v)| v.into_owned())
                })
                .expect("No code found in redirect");

            let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
                <html><body><h1>You can close this window now.</h1></body></html>";
            let _ = stream.write_all(response.as_bytes());

            *code_clone.lock().unwrap() = Some(code);
        });

        println!("{}",&auth_url);
        web_view::builder()
            .title("Microsoft Login")
            .content(Content::Url(&auth_url))
            .size(800, 600)
            .resizable(true)
            .user_data(())
            .invoke_handler(|_wv, _arg| Ok(()))
            .run()
            .unwrap();

        listener_thread.join().unwrap();
        Ok(code_holder.lock().unwrap().take().unwrap())
    }

    /// Exchange code for Minecraft access token
    pub fn authenticate(
        client_id: &str,
        app_id: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<Self, AuthError> {
        let request_payload = json!({
            "client_id": app_id,
            "redirect_uri": redirect_uri,
            "code": code,
            "grant_type": "authorization_code",
            "scope": "xboxlive.signin offline_access openid email profile"
        });

        let res = Self::authenticate_base(request_payload)?;

        let mut sess = Self::new();
        sess.access_token = res.get("access_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
        sess.username = res.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
        sess.uuid = res.get("uuid").and_then(|v| v.as_str()).unwrap_or("").to_string();
        sess.client_id = client_id.to_string();
        sess.refresh_token = res.get("refresh_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
        sess.app_id = app_id.to_string();
        sess.redirect_uri = redirect_uri.to_string();

        Ok(sess)
    }

    /// Core auth flow
    pub fn authenticate_base(request_token_payload: Value) -> Result<Value, AuthError> {
        let ms_token_res = Self::ms_request(
            "https://login.live.com/oauth20_token.srf",
            &request_token_payload,
            true,
        )
        .map_err(|e| match e {
            AuthError::Http(s) => AuthError::OutdatedToken(s),
            other => other,
        })?;

        let ms_refresh_token = ms_token_res.get("refresh_token").cloned();

        let xbox_payload = json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": format!("d={}", ms_token_res.get("access_token").and_then(Value::as_str).unwrap_or(""))
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        });

        let res_xbl = Self::ms_request("https://user.auth.xboxlive.com/user/authenticate", &xbox_payload, false)?;
        let xbl_token = res_xbl.get("Token").and_then(Value::as_str).unwrap_or_default().to_string();
        let xbl_user_hash = res_xbl
            .get("DisplayClaims")
            .and_then(|d| d.get("xui"))
            .and_then(|xui| xui.get(0))
            .and_then(|entry| entry.get("uhs"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let xsts_payload = json!({
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [xbl_token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        });

        let res_xsts = Self::ms_request("https://xsts.auth.xboxlive.com/xsts/authorize", &xsts_payload, false)?;
        let xsts_token = res_xsts.get("Token").and_then(Value::as_str).unwrap_or_default().to_string();
        let xsts_user_hash = res_xsts
            .get("DisplayClaims")
            .and_then(|d| d.get("xui"))
            .and_then(|xui| xui.get(0))
            .and_then(|entry| entry.get("uhs"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        if xbl_user_hash != xsts_user_hash {
            return Err(AuthError::InconsistentUserHash);
        }

        let mc_auth_payload = json!({
            "identityToken": format!("XBL3.0 x={};{}", xbl_user_hash, xsts_token)
        });

        let res_mc = Self::ms_request(
            "https://api.minecraftservices.com/authentication/login_with_xbox",
            &mc_auth_payload,
            false,
        )?;
        let mc_access_token = res_mc.get("access_token").and_then(Value::as_str).unwrap_or_default().to_string();

        let profile_res = Self::mc_request_profile(&mc_access_token)?;

        Ok(json!({
            "refresh_token": ms_refresh_token.unwrap_or(Value::Null),
            "access_token": mc_access_token,
            "username": profile_res.get("name").cloned().unwrap_or(Value::String(String::new())),
            "uuid": profile_res.get("id").cloned().unwrap_or(Value::String(String::new()))
        }))
    }

    pub fn ms_request(url: &str, payload: &Value, payload_url_encoded: bool) -> Result<Value, AuthError> {
        let client = Client::new();

        let resp = if payload_url_encoded {
            let mut pairs = form_urlencoded::Serializer::new(String::new());
            if let Some(obj) = payload.as_object() {
                for (k, v) in obj.iter() {
                    let s = match v {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        other => other.to_string(),
                    };
                    pairs.append_pair(k, &s);
                }
            }
            client.post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(pairs.finish())
                .send()
                .map_err(|e| AuthError::Http(e.to_string()))?
        } else {
            client.post(url).json(payload).send().map_err(|e| AuthError::Http(e.to_string()))?
        };

        let status = resp.status();
        let text = resp.text().map_err(|e| AuthError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(AuthError::Http(format!("status {}: {}", status.as_u16(), text)));
        }
        serde_json::from_str(&text).map_err(|e| AuthError::Other(e.to_string()))
    }

    pub fn mc_request_profile(bearer: &str) -> Result<Value, AuthError> {
        let client = Client::new();
        let resp = client
            .get("https://api.minecraftservices.com/minecraft/profile")
            .header("Authorization", format!("Bearer {}", bearer))
            .send()
            .map_err(|e| AuthError::Http(e.to_string()))?;

        let status = resp.status();
        let text = resp.text().map_err(|e| AuthError::Http(e.to_string()))?;
        match status {
            s if s.is_success() => serde_json::from_str(&text).map_err(|e| AuthError::Other(e.to_string())),
            StatusCode::NOT_FOUND => Err(AuthError::DoesNotOwnMinecraft(text)),
            StatusCode::UNAUTHORIZED => Err(AuthError::OutdatedToken(text)),
            _ => Err(serde_json::from_str::<Value>(&text)
                .map(|v| {
                    let err = v.get("errorMessage").or_else(|| v.get("error"))
                        .and_then(Value::as_str).unwrap_or("unknown error");
                    AuthError::Other(err.to_string())
                })
                .unwrap_or(AuthError::Other(format!("status {}: {}", status.as_u16(), text)))),
        }
    }
}
