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

pub mod password {
    use super::{Digest, Sha256};

    pub enum PswdError {
        TooShort,
        TooLong,
        NonAsciiDetected,
        TooLittleVariation,
    }

    const PSWD_MAX: usize = 24;
    const PSWD_MIN: usize = 8;

    pub fn hash_pswd(pswd: &[u8], salt: &[u8]) -> Vec<u8> {
        Sha256::digest([pswd, salt].concat()).as_slice().to_vec()
    }

    pub fn match_pswd(client_pswd: &str, db_salt: &str, db_pswd: &[u8]) -> bool {
        hash_pswd(client_pswd.as_bytes(), db_salt.as_bytes()) == db_pswd
    }

    // WARN these same checks are implemented in the frontend
    // so if they actually get checked here and fail
    // that means the user might be doing something nefarious
    //
    // we enforce len bounds so that the user doesnt pick a password too long and forgets it
    // or too short and easy for a bad actor to crack
    pub fn verify_len(pswd: &[u8]) -> Result<(), PswdError> {
        if pswd.len() > PSWD_MAX {
            return Err(PswdError::TooLong);
        } else if pswd.len() < PSWD_MIN {
            return Err(PswdError::TooShort);
        }

        Ok(())
    }

    pub fn verify_symbols(pswd: &[u8]) -> Result<(), PswdError> {
        if pswd.iter().all(|b| b.is_ascii_alphanumeric()) {
            return Err(PswdError::TooLittleVariation);
        }

        Ok(())
    }

    // we enforce ascii only chars for password interoperability
    pub fn verify_ascii(pswd: &[u8]) -> Result<(), PswdError> {
        if !pswd.is_ascii() {
            return Err(PswdError::NonAsciiDetected);
        }

        Ok(())
    }
}
