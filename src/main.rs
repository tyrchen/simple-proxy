use pingora::prelude::*;
use simple_proxy::SimpleProxy;
use tracing::info;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let mut server = Server::new(None)?;
    server.bootstrap();

    let sp = SimpleProxy {};

    let proxy_addr = "0.0.0.0:8080";
    let mut proxy = http_proxy_service(&server.configuration, sp);
    proxy.add_tcp(proxy_addr);

    info!("proxy server is running on {}", proxy_addr);

    server.add_service(proxy);

    server.run_forever();
}
