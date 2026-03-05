use hanabi_configs::{configs::Configs as Configuration, parse::Parse};
use pheasant::http::{
    ErrorStatus, Method, err_stt, header_value,
    server::{Request, Respond},
    status,
};
use pheasant::services::{Cors, MessageBodyInfo, ReadCookies, Resource, Socket, WriteCookies};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

pub enum Configs {
    Read,
    Write,
    Reset,
}

impl Configs {
    pub fn new(req: &Request) -> Result<Self, ErrorStatus> {
        Ok(match req.path().last().map(|s| s.as_str()) {
            Some("read") => Self::Read,
            Some("write") => Self::Write,
            Some("reset") => Self::Reset,
            _ => return err_stt!(?500),
        })
    }
}

impl Resource<Socket> for Configs {
    async fn get(
        self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        let Self::Read = self else {
            return err_stt!(?500);
        };

        let configs = serde_json::to_vec(&CONFIGS.clone()?).map_err(|_| err_stt!(500))?;
        MessageBodyInfo::new(&configs).dump_headers(resp.headers_mut());
        resp.body_mut().extend(configs);

        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Error {
    FailedToReadConfigFile,
    FailedToParseConfigFile,
}

impl From<Error> for ErrorStatus {
    fn from(_err: Error) -> Self {
        err_stt!(500)
    }
}

const CONFIGS: LazyLock<Result<Configuration, Error>> = LazyLock::new(|| {
    let data = std::fs::read("config.ini").map_err(|_| Error::FailedToReadConfigFile)?;

    Configuration::deserialize(&data).map_err(|_| Error::FailedToParseConfigFile)
});
