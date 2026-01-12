use pheasant::http::{
    ErrorStatus, Method, err_stt,
    server::{Request, Respond},
    status,
};

#[derive(Debug, Default)]
pub struct Login {
    pub(crate) name: String,
    pub(crate) pswd: String,
    pub(crate) persist_session: bool,
}

impl Login {
    pub fn parse(slice: &[u8]) -> Result<Self, ErrorStatus> {
        let mut idx = 0;

        Ok(Self {
            name: user_name(&slice[idx..], &mut idx)?,
            pswd: user_pswd(&slice[idx..], &mut idx)?,
            persist_session: persist_session(&slice[idx..], &mut idx)?,
        })
    }

    pub fn match_user(&self, name: &str, pswd: &str) -> Result<(), ErrorStatus> {
        if self.name == name && self.pswd == pswd {
            Ok(())
        } else {
            err_stt!(?500)
        }
    }
}

#[derive(Debug, Default)]
pub struct Register {
    pub(crate) name: String,
    pub(crate) pswd: String,
    pub(crate) auto_login: bool,
}

impl Register {
    pub fn parse(slice: &[u8]) -> Result<Self, ErrorStatus> {
        let mut idx = 0;
        validate_method_override(&slice[idx..], &mut idx)?;

        Ok(Self {
            name: user_name(&slice[idx..], &mut idx)?,
            pswd: user_pswd(&slice[idx..], &mut idx)?,
            auto_login: auto_login(&slice[idx..], &mut idx)?,
        })
    }
}

fn check_field(slice: &[u8], check: &[u8]) -> bool {
    slice.starts_with(check)
}

fn advance(idx: &mut usize, slice: &[u8]) -> usize {
    let old = *idx;
    *idx += slice.len();

    *idx - old
}

fn parse_value(slice: &[u8], idx: &mut usize) -> Result<String, ErrorStatus> {
    let amper = if !slice.contains(&b'&') {
        *idx + slice.len()
    } else {
        match slice.iter().position(|b| *b == b'&') {
            Some(amper) => amper,
            None => return err_stt!(?400),
        }
    };

    let value = str::from_utf8(&slice[..amper])
        .map_err(|_| err_stt!(400))
        .map(|s| s.to_owned());
    *idx += amper + 1;

    value
}

fn parse_bool(slice: &[u8], idx: &mut usize) -> Result<bool, ErrorStatus> {
    let amper = if !slice.contains(&b'&') {
        *idx + slice.len()
    } else {
        match slice.iter().position(|b| *b == b'&') {
            Some(amper) => amper,
            None => return err_stt!(?400),
        }
    };

    let boolean = match &slice[..amper] {
        b"true" => true,
        b"false" => false,
        _ => return err_stt!(?400),
    };
    *idx += amper + 1;

    Ok(boolean)
}

fn validate_method_override(slice: &[u8], idx: &mut usize) -> Result<(), ErrorStatus> {
    if !check_field(slice, b"method_override=put&") {
        return err_stt!(?400);
    }
    advance(idx, b"method_override=put&");

    Ok(())
}

fn user_name(slice: &[u8], idx: &mut usize) -> Result<String, ErrorStatus> {
    if !check_field(slice, b"user_name=") {
        return err_stt!(?400);
    }
    let diff = advance(idx, b"user_name=");

    parse_value(&slice[diff..], idx)
}

fn user_pswd(slice: &[u8], idx: &mut usize) -> Result<String, ErrorStatus> {
    if !check_field(slice, b"user_pswd") {
        return err_stt!(?400);
    }
    let diff = advance(idx, b"user_pswd=");

    parse_value(&slice[diff..], idx)
}

fn persist_session(slice: &[u8], idx: &mut usize) -> Result<bool, ErrorStatus> {
    if !check_field(slice, b"persist_session") {
        return err_stt!(?400);
    }
    let diff = advance(idx, b"persist_session=");

    parse_bool(&slice[diff..], idx)
}

fn auto_login(slice: &[u8], idx: &mut usize) -> Result<bool, ErrorStatus> {
    if !check_field(slice, b"auto_login") {
        return err_stt!(?400);
    }
    let diff = advance(idx, b"auto_login=");

    parse_bool(&slice[diff..], idx)
}
