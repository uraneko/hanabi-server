use pheasant::http::{
    Method, Protocol, err_stt,
    server::{Request, Respond},
    status,
};
use pheasant::services::{
    Server, Socket, http_error, parse,
    print::server::{print_req, print_resp},
    read_stream, req_buf, resp_write_stream,
};

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
        .await
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
                    http_error(err_stt!(400), &mut resp);
                    print_resp(&resp);
                    resp_write_stream(&resp, &mut stream, Method::Get)?;

                    continue;
                };
                let req = parse(req_buf);

                let req = match req {
                    Ok(req) => req,
                    Err(err) => {
                        http_error(err, &mut resp);
                        print_resp(&resp);
                        resp_write_stream(&resp, &mut stream, Method::Get)?;

                        continue;
                    }
                };
                print_req(&req);
                let method = req.method();

                // lookup should fetch whole service chains
                let service = match lookup(&req.path_str()) {
                    Ok(s) => s,
                    Err(err) => {
                        http_error(err, &mut resp);
                        print_resp(&resp);
                        resp_write_stream(&resp, &mut stream, method)?;

                        continue;
                    }
                };
                if let Err(err) = this.service(req, &mut resp, service).await {
                    http_error(err, &mut resp);
                    print_resp(&resp);
                    resp_write_stream(&resp, &mut stream, method)?;

                    continue;
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
