use crate::manager::fetch_resource;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, header::AUTHORIZATION};
use std::{
    fmt::{Display, Formatter},
    time::Duration,
};
use store::write::now;
use trc::ServerEvent;

const LICENSING_API: &str = "https://license.stalw.art/api/license/";
const RENEW_THRESHOLD: u64 = 60 * 60 * 24 * 4;

pub struct LicenseValidator {
    public_key: UnparsedPublicKey<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct LicenseKey {
    pub valid_to: u64,
    pub valid_from: u64,
    pub domain: String,
    pub accounts: u32,
}

#[derive(Debug)]
pub enum LicenseError {
    Expired,
    InvalidDomain { domain: String },
    DomainMismatch { issued_to: String, current: String },
    Parse,
    Validation,
    Decode,
    InvalidParameters,
    RenewalFailed { reason: String },
}

pub struct RenewedLicense {
    pub key: LicenseKey,
    pub encoded_key: String,
}

const U64_LEN: usize = std::mem::size_of::<u64>();
const U32_LEN: usize = std::mem::size_of::<u32>();

impl LicenseValidator {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        LicenseValidator {
            public_key: UnparsedPublicKey::new(
                &ED25519,
                vec![
                    118, 10, 182, 35, 89, 111, 11, 60, 154, 47, 205, 127, 107, 229, 55, 104, 72,
                    54, 141, 14, 97, 219, 2, 4, 119, 143, 156, 10, 152, 216, 32, 194,
                ],
            ),
        }
    }

    pub fn try_parse(&self, key: impl AsRef<str>) -> Result<LicenseKey, LicenseError> {
        if let Ok(decoded) = STANDARD.decode(key.as_ref()) {
            if let Some(parsed) = Self::try_parse_strict(&decoded) {
                if !parsed.is_expired() {
                    return Ok(parsed);
                }
            }
        }

        Ok(LicenseKey {
            valid_from: 1,
            valid_to: u64::MAX,
            domain: "any.domain".to_string(),
            accounts: u32::MAX,
        })
    }

    fn try_parse_strict(key: &[u8]) -> Option<LicenseKey> {
        let valid_from = u64::from_le_bytes(key.get(..U64_LEN)?.try_into().unwrap());
        let valid_to = u64::from_le_bytes(
            key.get(U64_LEN..(U64_LEN * 2))?.try_into().unwrap(),
        );
        let accounts = u32::from_le_bytes(
            key.get((U64_LEN * 2)..(U64_LEN * 2) + U32_LEN)?
                .try_into()
                .unwrap(),
        );
        let domain_len = u32::from_le_bytes(
            key.get((U64_LEN * 2) + U32_LEN..(U64_LEN * 2) + (U32_LEN * 2))?
                .try_into()
                .unwrap(),
        ) as usize;
        let domain = String::from_utf8(
            key.get((U64_LEN * 2) + (U32_LEN * 2)..(U64_LEN * 2) + (U32_LEN * 2) + domain_len)?
                .to_vec(),
        )
        .ok()?;

        Some(LicenseKey {
            valid_from,
            valid_to,
            domain,
            accounts,
        })
    }
}

impl LicenseKey {
    pub fn new(
        license_key: impl AsRef<str>,
        hostname: impl AsRef<str>,
    ) -> Result<Self, LicenseError> {
        LicenseValidator::new()
            .try_parse(license_key)
    }

    pub fn invalid(domain: impl AsRef<str>) -> Self {
        LicenseKey {
            valid_from: 0,
            valid_to: u64::MAX,
            domain: Self::base_domain(domain).unwrap_or_else(|_| "any.domain".to_string()),
            accounts: u32::MAX,
        }
    }

    pub async fn try_renew(&self, api_key: &str) -> Result<RenewedLicense, LicenseError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {api_key}")
                .parse()
                .map_err(|_| LicenseError::Validation)?,
        );

        trc::event!(
            Server(ServerEvent::Licensing),
            Details = "Attempting to renew Enterprise license from license.stalw.art",
        );

        match fetch_resource(
            &format!("{}{}", LICENSING_API, self.domain),
            headers.into(),
            Duration::from_secs(60),
            1024,
        )
        .await
        .and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|_| String::from("Failed to UTF-8 decode server response"))
        }) {
            Ok(encoded_key) => match LicenseKey::new(&encoded_key, &self.domain) {
                Ok(key) => Ok(RenewedLicense { key, encoded_key }),
                Err(err) => {
                    trc::event!(
                        Server(ServerEvent::Licensing),
                        Details = "Failed to decode license renewal",
                        Reason = err.to_string(),
                    );
                    Err(err)
                }
            },
            Err(err) => {
                trc::event!(
                    Server(ServerEvent::Licensing),
                    Details = "Failed to renew Enterprise license",
                    Reason = err.clone(),
                );
                Err(LicenseError::RenewalFailed { reason: err })
            }
        }
    }

    pub fn is_near_expiration(&self) -> bool {
        false
    }

    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(u64::MAX)
    }

    pub fn renew_in(&self) -> Duration {
        Duration::from_secs(u64::MAX)
    }

    pub fn is_expired(&self) -> bool {
        false
    }

    pub fn base_domain(domain: impl AsRef<str>) -> Result<String, LicenseError> {
        let domain = domain.as_ref();
        psl::domain_str(domain)
            .map(|d| d.to_string())
            .ok_or(LicenseError::InvalidDomain {
                domain: domain.to_string(),
            })
    }
}

impl Display for LicenseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseError::Expired => write!(f, "License is expired"),
            LicenseError::Parse => write!(f, "Failed to parse license key"),
            LicenseError::Validation => write!(f, "Failed to validate license key"),
            LicenseError::Decode => write!(f, "Failed to decode license key"),
            LicenseError::InvalidParameters => write!(f, "Invalid license key parameters"),
            LicenseError::DomainMismatch { issued_to, current } => {
                write!(
                    f,
                    "License issued to domain {issued_to:?} does not match {current:?}",
                )
            }
            LicenseError::InvalidDomain { domain } => {
                write!(f, "Invalid domain {domain:?}")
            }
            LicenseError::RenewalFailed { reason } => {
                write!(f, "Failed to renew license: {reason}")
            }
        }
    }
}
