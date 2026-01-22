use pheasant::http::{
    ErrorStatus, Method, err_stt, header_value,
    server::{Request, Respond},
    status,
};
use pheasant::services::{Cors, MessageBodyInfo, ReadCookies, Resource, Socket, WriteCookies};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, sqlite::SqliteRow};

mod operations;
mod prologue;

use operations::{
    db_cache_login_access, db_clear_login_access, db_clear_login_access_nameless,
    db_clear_login_refresh, db_query_field_availability, db_write_login_refresh,
    get_name_by_refresh, get_user_by_email, get_user_by_name, register_user,
};
use prologue::{Token, User, password};

// extern crate alloc;
// use alloc::borrow::Cow;

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
                    (query.remove_param("name"), query.remove_param("value"))
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

fn _cors(req: &Request, resp: &mut Respond) -> Result<(), ErrorStatus> {
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

type UnitResult = Result<(), ErrorStatus>;

async fn init(socket: &mut Socket, req: Request, resp: &mut Respond) -> Result<(), ErrorStatus> {
    // TODO check if request has a refresh token cookie
    let cookies = ReadCookies::from_headers(req.headers()).map_err(|_| err_stt!(400))?;
    if let Some(token) = cookies.get(b"ident_token") {
        let mut user = User::from_cookie(token, &mut socket.buffer)?;
        let hashed_token = Sha256::digest(user.access_token.as_bytes());

        // check token authenticity
        db_clear_login_access(&mut socket.conn, &user.name, hashed_token.as_slice())
            .await
            .map_err(|_| err_stt!(403))?;

        // renew session for user
        let access = Token::access()?;
        user.access_token = access.as_str();
        let user = user.serialize()?;
        resp.body_mut().extend(&user);
        MessageBodyInfo::new(&user).dump_headers(resp.headers_mut());
        WriteCookies::clear(b"ident_token", resp.headers_mut());
    } else if let Some(refresh) = cookies.get(Token::REFRESH.as_bytes()) {
        let db_refresh = Token::from_encoded(Token::REFRESH, refresh)?;
        db_refresh.hash(&mut socket.buffer);
        let row = extract_sole_row(
            get_name_by_refresh(&mut socket.conn, &socket.buffer)
                .await
                .map_err(|_| err_stt!(422))?,
        )?;
        let name = row.try_get("name").map_err(|_| err_stt!(500))?;

        _ = extract_sole_row(
            get_user_by_name(&mut socket.conn, name)
                .await
                .map_err(|_| err_stt!(500))?,
        )?;

        // NOTE cant provide the user email
        // since it is stored in the db in hashed format
        let access = Token::access()?;
        let user = User::serialized(&name, None, access.as_str())?;
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
    _req: Request,
    resp: &mut Respond,
    cache: CacheUser,
) -> UnitResult {
    let token = Token::from_json("ident_token", &cache)?;
    let mut cookie = WriteCookies::new();
    cookie.cookie(token.name(), token.as_slice());
    cookie.write(token.name(), resp.headers_mut());

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
        // BUG broken probably here
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
        _req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        let Self::Register(Register {
            name,
            email,
            pswd,
            verify,
            auto_login: _,
        }) = self
        else {
            return err_stt!(?500);
        };

        if pswd != verify {
            return err_stt!(?400);
        }

        password::verify_len(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        password::verify_ascii(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        password::verify_symbols(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        let salt = melh::salt_ascii(8, 16);
        let pswd = password::hash_pswd(pswd.as_bytes(), &salt);
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

        let user = extract_sole_row(if name.contains('@') {
            get_user_by_email(&mut socket.conn, Sha256::digest(name.as_bytes()).as_slice())
                .await
                .map_err(|_| err_stt!(422))?
        } else {
            get_user_by_name(&mut socket.conn, &name)
                .await
                .map_err(|_| err_stt!(422))?
        })?;

        let db_pswd = user.try_get("pswd").map_err(|_| err_stt!(503))?;
        let db_salt = user.try_get("salt").map_err(|_| err_stt!(503))?;

        if !password::match_pswd(&pswd, db_salt, db_pswd) {
            return err_stt!(?403);
        }
        let (name, email): (String, Option<String>) = if name.contains('@') {
            (user.try_get("name").map_err(|_| err_stt!(503))?, Some(name))
        } else {
            (name, None)
        };

        let access = Token::access()?;

        let user_state = User::serialized(
            &name,
            email.as_ref().map(|s: &String| s.as_str()),
            access.as_str(),
        )?;

        resp.body_mut().extend(&user_state);
        MessageBodyInfo::new(&user_state).dump_headers(resp.headers_mut());

        if persist_session {
            let refresh = Token::refresh()?;

            let mut token_cookie = WriteCookies::new();
            token_cookie
                .cookie(refresh.name(), refresh.as_slice())
                .samesite(0)
                .secure(true)
                .http_only(true)
                .max_age(3600 * 24 * 7);
            token_cookie.write(refresh.name(), resp.headers_mut());
            refresh.hash(&mut socket.buffer);
            db_write_login_refresh(&mut socket.conn, &name, &socket.buffer)
                .await
                .map_err(|_| err_stt!(403))?;
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

        // TODO replace this with the authorization service once it is implemented in pheasant
        let access = Token::from_encoded(Token::ACCESS, &access[7..access.len() - 1])?;
        access.hash(&mut socket.buffer);
        db_clear_login_access_nameless(&mut socket.conn, &socket.buffer)
            .await
            .map_err(|_| err_stt!(403))?;

        let cookies = ReadCookies::from_headers(req.headers()).map_err(|_| err_stt!(400))?;
        if let Some(refresh) = cookies.get(b"refresh_token") {
            let refresh = Token::from_encoded(Token::REFRESH, refresh)?;
            refresh.hash(&mut socket.buffer);
            db_clear_login_refresh(&mut socket.conn, &socket.buffer)
                .await
                .map_err(|_| err_stt!(403))?;

            WriteCookies::clear(b"refresh_token", resp.headers_mut());
        }

        resp.status(status!(204));

        Ok(())
    }
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
    name: String,
    value: String,
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CacheUser {
    name: String,
    email: Option<String>,
    access_token: String,
}

fn extract_sole_row(mut rows: Vec<SqliteRow>) -> Result<SqliteRow, ErrorStatus> {
    let Some(row) = rows.pop() else {
        return err_stt!(?403);
    };
    if !rows.is_empty() {
        return err_stt!(?403);
    }

    Ok(row)
}
