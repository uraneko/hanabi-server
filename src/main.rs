use pheasant::http::{
    Method, Protocol,
    server::{Request, Respond},
    status,
};
use pheasant::services::{
    Server, Socket, bad_request, error_status, parse, read_stream, req_buf, resp_write_stream,
};

mod auth;
mod index;
mod services;
use services::lookup;

#[derive(Debug)]
enum Error {
    ServerMishap,
    ServerBroken,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut socket = Socket::builder([127, 10, 10, 1], 6680)
        .database("data/main.db3")
        .build()
        .map_err(|_| Error::ServerMishap)?;

    socket.init_message();
    socket
        .event_loop(async |this: &mut Socket| {
            let mut resp = Respond::new(Protocol::Http11, status!(200));
            while let Ok((mut stream, _)) = read_stream(&this.socket) {
                resp.clear();
                // parse req
                let mut reader = std::io::BufReader::new(&mut stream);
                let Ok(req_buf) = req_buf(&mut reader) else {
                    bad_request(&mut resp);
                    resp_write_stream(&resp, &mut stream, Method::Get)?;
                    continue;
                };
                let req = parse(req_buf);
                let Ok(req) = req else {
                    bad_request(&mut resp);
                    resp_write_stream(&resp, &mut stream, Method::Get)?;
                    continue;
                };
                print_req(&req);
                let method = req.method();

                // lookup should fetch whole service chains
                let service = match lookup(&req.path_str()) {
                    Ok(s) => s,
                    Err(_err) => {
                        bad_request(&mut resp);
                        resp_write_stream(&resp, &mut stream, method)?;
                        continue;
                    }
                };
                if let Err(err) = this.service(req, &mut resp, service).await {
                    error_status(err, &mut resp);
                    resp_write_stream(&resp, &mut stream, method)?;
                }
                print_resp(&resp);
                resp_write_stream(&resp, &mut stream, method)?;
            }

            Ok(())
        })
        .await
        .map_err(|_| Error::ServerBroken)?;

    Ok(())
}

fn print_resp(resp: &Respond) {
    println!(
        "{} {} {}",
        resp.proto_cpy().as_str(),
        resp.status_cpy().code(),
        resp.status_cpy().text()
    );
    println!(
        "{}",
        str::from_utf8(resp.headers_ref()).unwrap_or_else(|_| "headers err".into())
    );
    println!(
        "{}",
        str::from_utf8(resp.body_ref()).unwrap_or_else(|_| "body err".into())
    );
    println!("***\n");
}

fn print_req(req: &Request) {
    println!(
        "{} - {} - {:?} - {}",
        req.method(),
        req.path_str(),
        req.query(),
        req.proto(),
    );
    req.headers()
        .iter()
        .inspect(|h| {
            println!(
                "{} -> {}",
                str::from_utf8(h.field_ref()).unwrap_or_else(|_| "field err".into()),
                str::from_utf8(h.value_ref()).unwrap_or_else(|_| "value err".into())
            )
        })
        .count();
    if let Some(body) = req.body() {
        println!(
            "{}",
            str::from_utf8(body).unwrap_or_else(|_| "body err".into())
        );
    }
    println!("---");
}
