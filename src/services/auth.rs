use crate::database_operations::{
    db_cache_login_access, db_clear_login_access, db_clear_login_access_nameless,
    db_clear_login_refresh, db_query_field_availability, db_write_login_refresh,
    get_name_by_refresh, get_user_by_email, get_user_by_name, register_user,
};
use makura::{Decode, Encode};
use pheasant::http::{
    ErrorStatus, Method, err_stt, header_value,
    server::{Request, Respond},
    status,
};
use pheasant::services::{Cors, MessageBodyInfo, ReadCookies, Resource, Socket, WriteCookies};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;

extern crate alloc;
use alloc::borrow::Cow;

#[derive(Debug, PartialEq, Eq)]
pub enum Auth {
    Cache(CacheUser),
    Query(QueryField),
    Init,
    Login(Login),
    Register(Register),
    Logout,
}

impl Auth {
    pub fn new(req: &mut Request) -> Result<Self, ErrorStatus> {
        use Method::*;

        Ok(match (req.method(), req.body()) {
            (Get, _) => {
                let Some(query) = req.query_mut() else {
                    return err_stt!(?400);
                };

                let (Some(field), Some(value)) =
                    (query.remove_param("field"), query.remove_param("value"))
                else {
                    return err_stt!(?400);
                };

                Self::Query(QueryField { name: field, value })
            }
            (Patch, Some(ref slice)) => {
                Self::Login(serde_json::from_slice(slice).map_err(|_| err_stt!(400))?)
            }
            (Put, Some(ref slice)) => {
                Self::Register(serde_json::from_slice(slice).map_err(|_| err_stt!(400))?)
            }
            (Post, None) => Self::Init,
            (Post, Some(ref slice)) => {
                Self::Cache(serde_json::from_slice(slice).map_err(|_| err_stt!(400))?)
            }
            (Delete, _) => Self::Logout,
            // 400 because a request body was expected and not found
            (m, _) if [Put, Patch].contains(&m) => return err_stt!(?400),

            _ => return err_stt!(?405),
        })
    }
}

fn cors(req: &Request, resp: &mut Respond) -> Result<(), ErrorStatus> {
    Cors::new()
        .origins(&[
            "http://localhost:3000",
            "http://localhost:3001",
            "http://localhost:3002",
        ])
        .headers(&["content-type", "content-length", "set-cookie"])
        .credentials(true)
        .methods(&[Method::Post, Method::Put])
        .cors(req.headers(), resp.headers_mut())
        .map_err(|_| err_stt!(403))
}

enum Error {
    MaliciousToken,
    BadToken,
    OutdatedToken,
}

fn verify_token(token: &[u8]) -> Result<(), Error> {
    Ok(())
}

fn extract_user(token: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(Vec::from(b""))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User<'a> {
    name: &'a str,
    email: Option<&'a str>,
    access_token: Cow<'a, str>,
}

impl<'a> User<'a> {
    pub fn new(name: &'a str, email: Option<&'a str>, token: &'a str) -> Self {
        Self {
            name,
            email,
            access_token: token.into(),
        }
    }
}

type UnitResult = Result<(), ErrorStatus>;

async fn init(socket: &mut Socket, req: Request, resp: &mut Respond) -> Result<(), ErrorStatus> {
    // TODO check if request has a refresh token cookie
    let cookies = ReadCookies::from_headers(req.headers()).map_err(|_| err_stt!(400))?;

    if let Some(token) = cookies.get(b"ident_token") {
        let user = token.decode(64).map_err(|_| err_stt!(422))?;
        let mut user: User = serde_json::from_slice(&user).map_err(|_| err_stt!(422))?;
        let hashed_token = Sha256::digest(user.access_token.as_bytes());

        // check token authenticity
        db_clear_login_access(&mut socket.conn, user.name, hashed_token.as_slice())
            .await
            .map_err(|_| err_stt!(403))?;

        // renew session for user
        let access = melh::salt_ascii(32, 48)
            .encode(64)
            .map_err(|_| err_stt!(422))?;
        let access = unsafe { str::from_utf8_unchecked(&access) };
        user.access_token = access.into();
        let user = serde_json::to_vec(&user).map_err(|_| err_stt!(503))?;

        resp.body_mut().extend(&user);
        MessageBodyInfo::new(&user).dump_headers(resp.headers_mut());

        let mut clear_cookie = WriteCookies::new();
        clear_cookie.cookie(b"ident_token", b"").max_age(0);
        clear_cookie.write(b"ident_token", resp.headers_mut());
    } else if let Some(refresh) = cookies.get(b"refresh_token") {
        let db_refresh = Sha256::digest(refresh.decode(64).map_err(|_| err_stt!(422))?);
        let rows = get_name_by_refresh(&mut socket.conn, db_refresh.as_slice())
            .await
            .map_err(|_| err_stt!(422))?;

        if rows.is_empty() {
            return err_stt!(?403);
        };
        if rows.len() > 1 {
            return err_stt!(?500);
        }
        let name = rows[0].try_get("name").map_err(|_| err_stt!(500))?;

        let users = get_user_by_name(&mut socket.conn, name)
            .await
            .map_err(|_| err_stt!(500))?;

        if users.is_empty() {
            return err_stt!(?403);
        };
        if users.len() > 1 {
            return err_stt!(?500);
        }
        // TODO encode all client bound tokens to base64 before sending them
        let access = generate_token(32, 48)?;
        let access = stringify_token(&access);
        let user = User::new(&name, None, access);
        let user = serde_json::to_vec(&user).map_err(|_| err_stt!(224))?;
        MessageBodyInfo::new(&user).dump_headers(resp.headers_mut());
    } else {
        MessageBodyInfo::new(b"")
            .force_mime("application/json")
            .map_err(|_| err_stt!(500))?
            .dump_headers(resp.headers_mut());
    }

    Ok(())
}

async fn cache(
    socket: &mut Socket,
    req: Request,
    resp: &mut Respond,
    cache: CacheUser,
) -> UnitResult {
    let token = serialize_token(&cache)?;

    let mut cookie = WriteCookies::new();
    cookie.cookie(b"ident_token", &token);
    cookie.write(b"ident_token", resp.headers_mut());

    let access = Sha256::digest(&cache.access_token);

    db_cache_login_access(&mut socket.conn, cache.name.as_str(), access.as_slice())
        .await
        .map_err(|_| err_stt!(500))?;

    Ok(())
}

impl Resource<Socket> for Auth {
    // checks if field value is available in db
    // returning true in response body means the value is free
    async fn get(
        self,
        socket: &mut Socket,
        _req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        let Self::Query(QueryField { name, value }) = self else {
            return err_stt!(?400);
        };

        if ["name", "email"]
            .into_iter()
            .all(|ss| !name.as_str().contains(ss))
        {
            resp.body_mut().extend(b"true");

            return Ok(());
        }

        let rows = db_query_field_availability(&mut socket.conn, &name, &value)
            .await
            .map_err(|_| err_stt!(500))?;

        let msg: &[u8] = match rows.len() {
            0 => b"true",
            1 => b"false",
            _ => return err_stt!(?500),
        };

        MessageBodyInfo::new(msg).dump_headers(resp.headers_mut());
        resp.body_mut().extend(msg);

        Ok(())
    }

    // inits an authless user session | logs user in to new session
    async fn post(
        self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        match self {
            Self::Init => init(socket, req, resp).await,
            Self::Cache(cache_) => cache(socket, req, resp, cache_).await,
            _ => return err_stt!(?500),
        }
    }

    // registers a new user
    async fn put(
        self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        let Self::Register(Register {
            name,
            email,
            pswd,
            verify,
            auto_login,
        }) = self
        else {
            return err_stt!(?500);
        };

        if pswd != verify {
            return err_stt!(?400);
        }

        verify_len(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        verify_ascii(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        verify_symbols(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        let salt = melh::salt_ascii(8, 16);
        let pswd = hash_pswd(pswd.as_bytes(), &salt);
        let date = chrono::Utc::now().timestamp_millis();
        let salt = str::from_utf8(&salt).map_err(|_| err_stt!(400))?;
        let email = email.map(|email| Sha256::digest(email.as_bytes()).as_slice().to_vec());

        let res = register_user(
            &mut socket.conn,
            &name,
            email.as_ref().map(|email| email.as_slice()),
            &pswd,
            salt,
            date,
        )
        .await;

        res.map_err(|_| err_stt!(503))?;

        resp.status(status!(201));
        // MessageBodyInfo::new(&[]).dump_headers(resp.headers_mut());

        // if auto_login {
        //     login(req, socket, resp, &name.as_bytes(), &pswd, false)?;
        // }

        Ok(())
    }

    async fn patch(
        self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        let Self::Login(Login {
            name,
            pswd,
            persist_session,
        }) = self
        else {
            return err_stt!(?400);
        };
        let cookies = ReadCookies::from_headers(req.headers()).map_err(|_| err_stt!(400))?;
        if cookies.contains(b"refresh_token") {
            return err_stt!(?403);
        }

        let mut users = if name.contains('@') {
            get_user_by_email(&mut socket.conn, Sha256::digest(name.as_bytes()).as_slice())
                .await
                .map_err(|_| err_stt!(422))?
        } else {
            get_user_by_name(&mut socket.conn, &name)
                .await
                .map_err(|_| err_stt!(422))?
        };
        let Some(user) = users.pop() else {
            return err_stt!(?403);
        };
        if !users.is_empty() {
            return err_stt!(?403);
        }

        let db_pswd = user.try_get("pswd").map_err(|_| err_stt!(503))?;
        let db_salt = user.try_get("salt").map_err(|_| err_stt!(503))?;

        if !match_pswd(&pswd, db_salt, db_pswd) {
            return err_stt!(?403);
        }
        let (name, email) = if name.contains('@') {
            (user.try_get("name").map_err(|_| err_stt!(503))?, Some(name))
        } else {
            (name, None)
        };

        let access = melh::salt_ascii(32, 48);
        let access = unsafe { str::from_utf8_unchecked(&access) };

        let user_state = User::new(&name, email.as_ref().map(|s| s.as_str()), access);
        let user_state = serde_json::to_vec(&user_state).map_err(|_| err_stt!(422))?;

        resp.body_mut().extend(&user_state);
        MessageBodyInfo::new(&user_state).dump_headers(resp.headers_mut());

        if persist_session {
            let refresh = melh::salt_ascii(32, 64)
                .encode(64)
                .map_err(|_| err_stt!(422))?;
            let refresh = unsafe { str::from_utf8_unchecked(&refresh) };

            let mut token_cookie = WriteCookies::new();
            token_cookie
                .cookie(b"refresh_token", refresh.as_bytes())
                .samesite(0)
                .secure(true)
                .http_only(true)
                .max_age(3600 * 24 * 7);
            token_cookie.write(b"refresh_token", resp.headers_mut());

            let refresh = Sha256::digest(&refresh);
            let res = db_write_login_refresh(&mut socket.conn, &name, &refresh).await;
            println!("{:?}", res);
            res.map_err(|_| err_stt!(403))?;
        }

        Ok(())
    }

    async fn delete(
        self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        if self != Self::Logout {
            return err_stt!(?400);
        };

        let Some(access) = header_value(req.headers(), b"authorization") else {
            return err_stt!(?403);
        };

        let access = &access[7..access.len() - 2];
        let access = access.decode(64).map_err(|_| err_stt!(422))?;
        let access = Sha256::digest(&access);
        db_clear_login_access_nameless(&mut socket.conn, access.as_slice())
            .await
            .map_err(|_| err_stt!(403))?;

        let cookies = ReadCookies::from_headers(req.headers()).map_err(|_| err_stt!(400))?;
        if let Some(refresh) = cookies.get(b"refresh_token") {
            let refresh = refresh.decode(64).map_err(|_| err_stt!(422))?;
            let refresh = Sha256::digest(refresh);
            db_clear_login_refresh(&mut socket.conn, &refresh)
                .await
                .map_err(|_| err_stt!(403))?;

            let mut clear_cookie = WriteCookies::new();
            clear_cookie.cookie(b"refresh_token", b"").max_age(0);
            clear_cookie.write(b"refresh_token", resp.headers_mut());
        }

        resp.status(status!(204));

        Ok(())
    }
}

fn hash_pswd(pswd: &[u8], salt: &[u8]) -> Vec<u8> {
    Sha256::digest([pswd, salt].concat()).as_slice().to_vec()
}

fn match_pswd(client_pswd: &str, db_salt: &str, db_hash: &[u8]) -> bool {
    hash_pswd(client_pswd.as_bytes(), db_salt.as_bytes()) == db_hash
}

pub enum PswdError {
    TooShort,
    TooLong,
    NonAsciiDetected,
    TooLittleVariation,
}

const PSWD_MAX: usize = 24;
const PSWD_MIN: usize = 8;

// WARN these same checks are implemented in the frontend
// so if they actually get checked here and fail
// that means the user might be doing something nefarious
//
// we enforce len bounds so that the user doesnt pick a password too long and forgets it
// or too short and easy for a bad actor to crack
fn verify_len(pswd: &[u8]) -> Result<(), PswdError> {
    if pswd.len() > PSWD_MAX {
        return Err(PswdError::TooLong);
    } else if pswd.len() < PSWD_MIN {
        return Err(PswdError::TooShort);
    }

    Ok(())
}

fn verify_symbols(pswd: &[u8]) -> Result<(), PswdError> {
    if pswd.iter().all(|b| b.is_ascii_alphanumeric()) {
        return Err(PswdError::TooLittleVariation);
    }

    Ok(())
}

// we enforce ascii only chars for password interoperability
fn verify_ascii(pswd: &[u8]) -> Result<(), PswdError> {
    if !pswd.is_ascii() {
        return Err(PswdError::NonAsciiDetected);
    }

    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Login {
    #[serde(rename = "user_name")]
    pub(crate) name: String,
    #[serde(rename = "user_pswd")]
    pub(crate) pswd: String,
    pub(crate) persist_session: bool,
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Register {
    #[serde(rename = "user_name")]
    pub(crate) name: String,
    #[serde(rename = "user_email")]
    pub(crate) email: Option<String>,
    #[serde(rename = "user_pswd")]
    pub(crate) pswd: String,
    #[serde(rename = "verify_pswd")]
    pub(crate) verify: String,
    pub(crate) auto_login: bool,
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct QueryField {
    #[serde(rename = "field")]
    name: String,
    value: String,
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CacheUser {
    name: String,
    email: Option<String>,
    access_token: String,
}

fn break_ident_token(token: &[u8]) -> (&str, Option<&str>) {
    let Some(pos) = token.iter().position(|b| *b == 10) else {
        return (str::from_utf8(token).unwrap_or_else(|_| ""), None);
    };

    let name = str::from_utf8(&token[..pos]).unwrap_or_else(|_| "");
    let email = str::from_utf8(&token[pos + 1..]).ok();

    (name, email)
}

// generates a new random token value with min < len < max
fn generate_token(min: usize, max: usize) -> Result<Vec<u8>, ErrorStatus> {
    let access = melh::salt_ascii(min, max);
    let access = access.encode(64).map_err(|_| err_stt!(422))?;

    Ok(access)
}

// stringifies token slice into &str
// WARN uses unchecked version because this is only used with generate token which uses salt_ascii
// so the result is always assured to be valid
fn stringify_token(token: &[u8]) -> &str {
    unsafe { str::from_utf8_unchecked(&token) }
}

fn serialize_token(s: impl serde::Serialize) -> Result<Vec<u8>, ErrorStatus> {
    let token = serde_json::to_vec(&s).map_err(|_| err_stt!(422))?;
    let token64 = token.encode(64).map_err(|_| err_stt!(422))?;

    Ok(token64)
}
