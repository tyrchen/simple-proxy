use clap::Parser;
use pingora::{listeners::tls::TlsSettings, prelude::*, server::configuration::ServerConf};
use simple_proxy::{HealthService, SimpleProxy, conf::ProxyConfigResolved};
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

    let conf = {
        let ca_file = config.global.tls.as_ref().and_then(|tls| tls.ca.clone());
        ServerConf {
            ca_file,
            ..Default::default()
        }
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let rp = SimpleProxy::try_new(config)?;
    let health_service = HealthService::new(rp.route_table().clone());

    let mut proxy = http_proxy_service(&server.configuration, rp);
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
    server.add_service(health_service);

    server.run_forever();
}
