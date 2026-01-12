use pheasant::http::{
    ErrorStatus, Method, err_stt,
    server::{Request, Respond},
    status,
};
use pheasant::services::{
    Cors, MessageBodyInfo, ReadCookies, Resource, Service, Socket, WriteCookies,
};
use std::io::Read;

// fetch a frontend file
pub struct SrcFile<'a> {
    path: &'a str,
    ext: &'a str,
}

impl<'a> SrcFile<'a> {
    pub fn new(path: &'a str) -> Result<Self, ErrorStatus> {
        let path = if path == "/" {
            "index.html"
        } else {
            &path[1..]
        };
        let ext = file_ext(path)?;

        Ok(Self { path, ext })
    }
}

fn change_dir(path: &str) -> Result<(), ErrorStatus> {
    std::env::set_current_dir(path).map_err(|_| err_stt!(500))
}

impl<'a> Resource<Socket> for SrcFile<'a> {
    async fn get(
        &self,
        socket: &mut Socket,
        req: Request,
        resp: &mut Respond,
    ) -> Result<(), ErrorStatus> {
        change_dir("build")?;
        let n = read_dyn(self.path, resp.body_mut())?;

        MessageBodyInfo::with_len(n)
            .mime_from_ext(self.ext)
            .dump_headers(resp.headers_mut());
        change_dir("..")?;

        Ok(())
    }
}

// reads a file dynamically
// i.e., it rereads the file contents at the time a request for it is made
// file is not statically included in the server binary
fn read_dyn(path: &str, buf: &mut Vec<u8>) -> Result<usize, ErrorStatus> {
    std::fs::File::open(path)
        .map_err(|_| err_stt!(500))?
        .read_to_end(buf)
        .map_err(|_| err_stt!(500))
}

fn file_ext(file: &str) -> Result<&str, ErrorStatus> {
    let Some(dot) = file
        .chars()
        .rev()
        .position(|ch| ch == '.')
        .map(|pos| file.len() - pos)
    else {
        return err_stt!(?500);
    };

    // instead of doing len - pos - 1 in the map above
    // then doing dot + 1 here
    // we remove both operations
    Ok(&file[dot..])
}
