use clap::Parser;
use pingora::prelude::*;
use simple_proxy::{SimpleProxy, conf::ProxyConfig};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long)]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let mut server = Server::new(None)?;
    server.bootstrap();

    let config = ProxyConfig::load(args.config)?;
    let sp = SimpleProxy::new(config);
    let port = sp.config().load().global.port;

    let proxy_addr = format!("0.0.0.0:{}", port);
    let mut proxy = http_proxy_service(&server.configuration, sp);
    proxy.add_tcp(&proxy_addr);

    info!("proxy server is running on {}", proxy_addr);

    server.add_service(proxy);

    server.run_forever();
}
