use makura::{Decode, Encode};
use pheasant::http::{ErrorStatus, err_stt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
pub struct User<'a> {
    pub name: &'a str,
    pub email: Option<&'a str>,
    pub access_token: &'a str,
}

impl<'a> User<'a> {
    pub fn new(name: &'a str, email: Option<&'a str>, access_token: &'a str) -> Self {
        Self {
            name,
            email,
            access_token,
        }
    }

    pub fn from_cookie(cookie: &[u8], buf: &'a mut Vec<u8>) -> Result<Self, ErrorStatus> {
        buf.clear();
        cookie.decode_with(buf, 64).map_err(|_| err_stt!(422))?;
        let token = serde_json::from_slice(buf).map_err(|_| err_stt!(422))?;

        Ok(token)
    }

    pub fn serialized(
        name: &'a str,
        email: Option<&'a str>,
        access_token: &'a str,
    ) -> Result<Vec<u8>, ErrorStatus> {
        serde_json::to_vec(&Self::new(name, email, access_token)).map_err(|_| err_stt!(422))
    }

    pub fn serialize(self) -> Result<Vec<u8>, ErrorStatus> {
        serde_json::to_vec(&self).map_err(|_| err_stt!(422))
    }
}

#[derive(Debug)]
pub struct Token {
    pub name: &'static str,
    pub token: Vec<u8>,
}

impl Token {
    pub const ACCESS: &str = "access_token";
    pub const REFRESH: &str = "refresh_token";

    pub fn access() -> Result<Self, ErrorStatus> {
        let name = Self::ACCESS;
        let token = melh::salt_ascii(32, 48)
            .encode(64)
            .map_err(|_| err_stt!(422))?;

        Ok(Self { name, token })
    }

    pub fn refresh() -> Result<Self, ErrorStatus> {
        let name = Self::REFRESH;
        let token = melh::salt_ascii(32, 64)
            .encode(64)
            .map_err(|_| err_stt!(422))?;

        Ok(Self { name, token })
    }

    pub fn from_encoded(name: &'static str, slice: &[u8]) -> Result<Self, ErrorStatus> {
        Ok(Self {
            name,
            token: slice.decode(64).map_err(|_| err_stt!(422))?,
        })
    }

    /// this is different from the other Token constructors
    /// in that this fun takes some json type and tokenizes it
    /// while the others generate random ascii tokens, or decode existing ones
    pub fn from_json(name: &'static str, json: impl serde::Serialize) -> Result<Self, ErrorStatus> {
        let token = serde_json::to_vec(&json).map_err(|_| err_stt!(422))?;
        let token = token.encode(64).map_err(|_| err_stt!(422))?;

        Ok(Self { name, token })
    }

    pub fn as_slice(&self) -> &[u8] {
        self.token.as_slice()
    }

    // stringifies token slice into &str
    // WARN uses unchecked version because this is only used with generate token which uses salt_ascii
    // so the result is always assured to be valid
    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.token) }
    }

    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    pub fn hash(&self, buf: &mut Vec<u8>) {
        buf.clear();
        buf.extend(Sha256::digest(&self.token).as_slice());
    }
}
