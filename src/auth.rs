// aes_gcm
use aes_gcm::{
    aead::{AeadMut, OsRng},
    AeadCore, Aes256Gcm,
};

// base64
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

// crate
use crate::config::PluginConfiguration;
use crate::config::UserPasswordCombination;

// log
use log::warn;

// proxy_wasm
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// std
use std::sync::Arc;

/// This is the basic auth context
pub struct BasicAuthContext {
    pub config: Arc<PluginConfiguration>,
}

impl HttpContext for BasicAuthContext {
    /// Handle the HTTP request headers
    ///
    /// # Arguments
    ///
    /// * `_` - The number of headers
    /// * `_` - Whether the headers are streaming
    ///
    /// # Returns
    ///
    /// The action to take
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let path = self.get_http_request_header(":path").unwrap_or_default();
        if path == "/healthcheck" {
            self.send_http_response(200, vec![], None);
            return Action::Continue;
        }

        // Look for session cookie
        let session_cookie = self.get_auth_cookie();
        let nonce = self.get_nonce();

        // If the session cookie and nonce are found, try to get the session from the cookie
        if session_cookie.is_ok() && nonce.is_ok() {
            match self
                .get_session_from_cookie(session_cookie.unwrap().as_str(), nonce.unwrap().as_str())
            {
                Ok(username_password_combination) => {
                    // Check if the user is authorized
                    if self.is_authorized(
                        &username_password_combination.username,
                        &username_password_combination.password,
                    ) {
                        return Action::Continue;
                    }
                }
                Err(e) => warn!("error getting session from cookie: {}", e),
            }
        }

        // If the session cookie and nonce are not found, check the basic auth header and create a session if valid
        if let Some(authorization_header) = self.get_http_request_header("Authorization") {
            if authorization_header.starts_with("Basic ") {
                let (username, password) =
                    match self.extract_basic_auth_credentials(&authorization_header) {
                        Some(credentials) => credentials,
                        None => {
                            warn!("invalid basic auth credentials");
                            return Action::Pause;
                        }
                    };

                // Check if the user is authorized, and create a session if so
                if self.is_authorized(&username, &password) {
                    self.create_session_and_redirect(
                        &UserPasswordCombination { username, password },
                        Some(path),
                    );
                    return Action::Pause;
                }
            }
        }

        // If the user is not authorized, send a challenge
        self.send_auth_challenge();
        Action::Pause
    }
}

impl BasicAuthContext {
    /// Create a session and redirect to the root path
    ///
    /// # Arguments
    ///
    /// * `username_password_combination` - The username and password combination
    /// * `path` - The path to redirect to
    fn create_session_and_redirect(
        &mut self,
        username_password_combination: &UserPasswordCombination,
        redirect_to: Option<String>,
    ) {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let encoded_nonce = BASE64.encode(nonce.as_slice());

        let mut cipher = self.config.aes_key.reveal().clone();
        let encrypted_cookie = cipher
            .encrypt(
                &nonce,
                serde_json::to_vec(&username_password_combination)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        let encoded_cookie = BASE64.encode(encrypted_cookie.as_slice());

        self.send_http_response(
            307,
            vec![
                ("Location", redirect_to.unwrap_or("/".to_string()).as_str()),
                (
                    "Set-Cookie",
                    format!(
                        "{}={}; Path=/; HttpOnly; Secure; Max-Age={}",
                        self.config.cookie_name, encoded_cookie, self.config.cookie_duration
                    )
                    .as_str(),
                ),
                (
                    "Set-Cookie",
                    format!(
                        "{}-nonce={}; Path=/; HttpOnly; Secure; Max-Age={}",
                        self.config.cookie_name, encoded_nonce, self.config.cookie_duration
                    )
                    .as_str(),
                ),
                ("Cache-Control", "no-cache"),
            ],
            None,
        );
    }

    /// Get the session from the cookie
    ///
    /// # Arguments
    ///
    /// * `cookie` - The cookie value
    /// * `nonce` - The nonce value
    ///
    /// # Returns
    ///
    /// The username and password combination if the session is valid, an error otherwise
    fn get_session_from_cookie(
        &mut self,
        cookie: &str,
        nonce: &str,
    ) -> Result<UserPasswordCombination, String> {
        let mut cipher = self.config.aes_key.reveal().clone();

        let decoded_nonce = match BASE64.decode(nonce) {
            Ok(decoded_nonce) => decoded_nonce,
            Err(e) => return Err(format!("failed to decode nonce: {}", e)),
        };
        let nonce = aes_gcm::Nonce::from_slice(decoded_nonce.as_slice());

        let decoded_cookie = match BASE64.decode(cookie) {
            Ok(decoded_cookie) => decoded_cookie,
            Err(e) => return Err(format!("failed to decode cookie: {}", e)),
        };

        let decrypted = match cipher.decrypt(nonce, decoded_cookie.as_slice()) {
            Ok(decrypted) => decrypted,
            Err(e) => return Err(format!("failed to decrypt cookie: {}", e)),
        };
        let username_password_combination: UserPasswordCombination =
            match serde_json::from_slice(&decrypted) {
                Ok(username_password_combination) => username_password_combination,
                Err(e) => return Err(format!("failed to parse session: {}", e)),
            };

        Ok(username_password_combination)
    }

    /// Extract the basic auth credentials from the header
    ///
    /// # Arguments
    ///
    /// * `header` - The basic auth header
    ///
    /// # Returns
    ///
    /// A tuple with the `username` and `password` if the credentials are valid, `None` otherwise
    fn extract_basic_auth_credentials(&self, header: &str) -> Option<(String, String)> {
        let decoded = BASE64.decode(header[6..].trim()).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let parts: Vec<&str> = decoded_str.split(':').collect();
        Some((parts[0].to_string(), parts[1].to_string()))
    }

    /// Check if the user is authorized
    ///
    /// # Arguments
    ///
    /// * `username` - The username
    /// * `password` - The password
    ///
    /// # Returns
    ///
    /// `true` if the user is authorized, `false` otherwise
    fn is_authorized(&self, username: &str, password: &str) -> bool {
        self.config
            .allowed_users
            .contains(&UserPasswordCombination {
                username: username.to_string(),
                password: password.to_string(),
            })
    }

    /// Send an unauthorized response to collect credentials
    fn send_auth_challenge(&mut self) {
        self.send_http_response(
            401,
            vec![
                ("WWW-Authenticate", "Basic realm=\"Restricted Area\""),
                ("Cache-Control", "no-cache"),
            ],
            None,
        );
    }

    /// Get the cookie of the HTTP request by name
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the cookie to search for
    ///
    /// # Returns
    ///
    /// The value of the cookie if found, `None` otherwise
    fn get_cookie(&self, name: &str) -> Option<String> {
        let headers = self.get_http_request_headers();
        for (key, value) in headers.iter() {
            if key.to_lowercase().trim() == "cookie" {
                let cookies: Vec<_> = value.split(';').collect();
                for cookie_string in cookies {
                    let cookie_name_end = cookie_string.find('=').unwrap_or(0);
                    let cookie_name = &cookie_string[0..cookie_name_end];
                    if cookie_name.trim() == name {
                        return Some(
                            cookie_string[(cookie_name_end + 1)..cookie_string.len()].to_owned(),
                        );
                    }
                }
            }
        }
        None
    }

    /// Get the auth cookie from the request
    ///
    /// # Returns
    ///
    /// The value of the auth cookie if found, an error otherwise
    fn get_auth_cookie(&self) -> Result<String, String> {
        self.get_cookie(self.config.cookie_name.as_str())
            .ok_or(format!(
                "auth cookie not found for {}",
                self.config.cookie_name
            ))
    }

    /// Get the encoded nonce from the cookie
    ///
    /// # Returns
    ///
    /// The value of the nonce cookie if found, an error otherwise
    pub fn get_nonce(&self) -> Result<String, String> {
        self.get_cookie(format!("{}-nonce", self.config.cookie_name).as_str())
            .ok_or(format!(
                "nonce cookie not found for {}",
                self.config.cookie_name
            ))
    }
}

impl Context for BasicAuthContext {}
