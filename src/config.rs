// aes_gcm
use aes_gcm::{Aes256Gcm, KeyInit};

// core
use core::fmt;

// sec
use sec::Secret;

// std
use std::fmt::Debug;

// serde
use serde::{Deserialize, Deserializer};

/// Struct that holds the configuration for the plugin. It is loaded from the config file `envoy.yaml`
#[derive(Clone, Debug, Deserialize)]
pub struct PluginConfiguration {
    // Cookie settings
    /// The cookie name that will be used for the session cookie
    pub cookie_name: String,
    /// The cookie duration in seconds
    pub cookie_duration: u64,

    /// The allowed users
    pub allowed_users: Vec<UserPasswordCombination>,

    /// AES Key
    #[serde(deserialize_with = "deserialize_aes_key")]
    pub aes_key: Secret<Aes256Gcm>,
}

/// Struct that holds a user and password combination
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, serde::Serialize)]
pub struct UserPasswordCombination {
    /// The username
    pub username: String,
    /// The password
    pub password: String,
}

/// Deserialize a base64 encoded 32 byte AES key
fn deserialize_aes_key<'de, D>(deserializer: D) -> Result<Secret<Aes256Gcm>, D::Error>
where
    D: Deserializer<'de>,
{
    use base64::{engine::general_purpose::STANDARD as base64engine, Engine as _};
    use serde::de::{Error, Visitor};

    struct AesKeyVisitor;

    impl<'de> Visitor<'de> for AesKeyVisitor {
        type Value = Secret<Aes256Gcm>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a base64 string encoding a 32 byte AES key`")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let aes_key = base64engine.decode(s).map_err(Error::custom)?;
            let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| {
                Error::custom(format!("{e}, got {} bytes, expected 32", aes_key.len()))
            })?;

            Ok(Secret::new(cipher))
        }
    }

    // using a visitor here instead of just <&str>::deserialize
    // makes sure that any error message contains the field name
    deserializer.deserialize_str(AesKeyVisitor)
}
