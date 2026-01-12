use pheasant::http::{
    ErrorStatus, Method, err_stt,
    server::{Request, Respond},
    status,
};
use pheasant::services::{
    Cors, MessageBodyInfo, ReadCookies, Resource, Service, Socket, WriteCookies,
};
use sha2::{Digest, Sha256};

mod parse;
use parse::{Login, Register};

pub enum Auth {
    Authless,
    Login(Login),
    Register(Register),
    Logout,
}

impl Auth {
    pub fn new(method: Method, data: Option<&[u8]>) -> Result<Self, ErrorStatus> {
        let method = if data
            .as_ref()
            .map(|data| data.starts_with(b"method_override=put"))
            .unwrap_or_else(|| false)
        {
            Method::Put
        } else {
            method
        };

        Ok(match (method, data) {
            (Method::Post, Some(ref slice)) => Self::Login(Login::parse(slice)?),
            (Method::Post, None) => Self::Authless,
            (Method::Put, Some(ref slice)) => Self::Register(Register::parse(slice)?),
            // 400 because a request body was expected and not found
            (Method::Put, None) => return err_stt!(?400),
            (Method::Delete, _) => Self::Logout,

            _ => return err_stt!(?405),
        })
    }

    pub fn is_register(&self) -> bool {
        core::mem::discriminant(self)
            == core::mem::discriminant(&Self::Register(Register::default()))
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
    Ok(Vec::from(b"scarecrow"))
}

fn login_authless(req: Request, resp: &mut Respond) -> Result<(), ErrorStatus> {
    // TODO check if request has a token cookie
    let cookies = ReadCookies::from_headers(req.headers()).map_err(|_| err_stt!(400))?;

    if let Some(token) = cookies.get(b"tkn") {
        // check token authenticity then
        // renew session for user
        verify_token(token).map_err(|_| err_stt!(500))?;
        let name = extract_user(token).map_err(|_| err_stt!(500))?;
        MessageBodyInfo::new(&name).dump_headers(resp.headers_mut());
    } else {
        MessageBodyInfo::new(&[]).dump_headers(resp.headers_mut());
    }

    Ok(())
}

fn login(
    req: Request,
    socket: &mut Socket,
    resp: &mut Respond,
    name: &[u8],
    pswd: &[u8],
    persist: bool,
) -> Result<(), ErrorStatus> {
    Ok(())
}

impl Resource<Socket> for Auth {
    // inits an authless user session | logs user in to new session
    async fn post(
        self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        if self.is_register() {
            return self.put(socket, req, resp).await;
        }

        match self {
            Self::Authless => {}
            Self::Login(Login {
                name,
                pswd,
                persist_session,
            }) => login(
                req,
                socket,
                resp,
                name.as_bytes(),
                pswd.as_bytes(),
                persist_session,
            )?,
            _ => unreachable!(
                "logout is through delete and register has been redirected above this match"
            ),
        }

        let mut stt = socket
            .conn
            .prepare("select * from users where name = ? and password = ?")
            .map_err(|_| err_stt!(500))?;
        stt.bind_iter::<_, (_, &str)>([(1, name.as_str().into()), (2, pswd.as_str().into())])
            .map_err(|_| err_stt!(500))?;
        match stt.next() {
            Ok(sqlite::State::Row) => (),
            Ok(sqlite::State::Done) | Err(_) => return err_stt!(?500),
        }
        let salt = generate_salt();
        let client_pswd = hash_pswd(pswd, salt);

        let (Ok(name), Ok(pswd)) = (
            stt.read::<String, _>("name"),
            stt.read::<String, _>("password"),
        ) else {
            return err_stt!(?500);
        };
        if pswd != client_pswd {
            return err_stt!(?500);
        }
        let cookies = ReadCookies::from_headers(req.headers()).map_err(|_| err_stt!(400))?;
        if !cookies.contains(b"tkn") {
            let mut cookies = WriteCookies::new();
            // set a traveller token cookie for the recent user
            cookies
                .cookie(b"tkn", b"boukennoshou")
                .samesite(0)
                .secure(true)
                .max_age(1200)
                .partitioned(true);
            _ = cookies.write(b"tkn", resp.headers_mut());
        }

        Ok(())
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
            pswd,
            auto_login,
        }) = self
        else {
            return err_stt!(?500);
        };

        verify_len(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        verify_ascii(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        verify_symbols(pswd.as_bytes()).map_err(|_| err_stt!(500))?;
        let salt = generate_salt();
        let pswd = hash_pswd(pswd.as_bytes(), salt);
        let date = chrono::Utc::now().timestamp_millis();

        let mut stt = socket
            .conn
            .prepare("insert into users values (:name, :password, :salt, :created_on)")
            .map_err(|_| err_stt!(500))?;
        stt.bind_iter::<_, (_, sqlite::Value)>([
            (":name", name.into()),
            (":password", pswd.into()),
            (":salt", salt.into()),
            (":created_on", date.into()),
        ])
        .map_err(|_| err_stt!(500))?;
        stt.next().map_err(|_| err_stt!(500))?;
        resp.status(status!(201));
        MessageBodyInfo::new(&[]).dump_headers(resp.headers_mut());

        // if auto_login {
        //     login(req, socket, resp, &name.as_bytes(), &pswd, false)?;
        // }

        Ok(())
    }
}

fn generate_salt() -> &'static [u8] {
    b"salt"
}

fn hash_pswd(pswd: &[u8], salt: &[u8]) -> Vec<u8> {
    Sha256::digest([pswd, salt].concat()).as_slice().to_vec()
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
