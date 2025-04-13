use clap::Parser;
use pingora::{listeners::tls::TlsSettings, prelude::*};
use simple_proxy::{SimpleProxy, conf::ProxyConfigResolved};
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
    let config = ProxyConfigResolved::load(args.config)?;
    let tls_settings = {
        match config.global.tls.as_ref() {
            None => None,
            Some(tls) => {
                let mut tls_settings = TlsSettings::intermediate(&tls.cert, &tls.key)?;
                tls_settings.enable_h2();
                Some(tls_settings)
            }
        }
    };
    let proxy_addr = format!("0.0.0.0:{}", config.global.port);

    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, SimpleProxy::new(config));
    match tls_settings {
        Some(tls_settings) => {
            proxy.add_tls_with_settings(&proxy_addr, None, tls_settings);
        }
        None => {
            proxy.add_tcp(&proxy_addr);
        }
    }

    info!("proxy server is running on {}", proxy_addr);

    server.add_service(proxy);

    server.run_forever();
}
