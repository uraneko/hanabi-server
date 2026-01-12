use crate::{auth::Auth, index::SrcFile};
use pheasant::http::{
    ErrorStatus, Method, err_stt,
    server::{Request, Respond},
    status,
};
use pheasant::services::{
    Cors, MessageBodyInfo, ReadCookies, Resource, Service, Socket, WriteCookies,
};

impl Service<Socket> for Services {
    async fn serve(
        &self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        match self {
            Self::Auth => {
                Auth::new(req.method(), req.body())?
                    .run(socket, req, resp)
                    .await
            }
            Self::SrcFile => SrcFile::new(&req.path_str())?.run(socket, req, resp).await,
        }
    }
}

#[derive(Debug)]
pub enum Services {
    Auth,
    SrcFile,
}

pub fn lookup(path: &str) -> Result<Services, ErrorStatus> {
    Ok(match path {
        "/auth" => Services::Auth,
        p if ["/", "/index.html"].contains(&p) || p.starts_with("/assets/") => Services::SrcFile,
        _ => return err_stt!(?404),
    })
}
