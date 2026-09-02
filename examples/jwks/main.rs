use anyhow::Context;
use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Automatic JWKS reload example")]
pub struct CliArguments {
    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity,

    #[arg(
        short,
        long,
        help = "Base URL of IdP, e.g. https://keycloak.example.org/realms/your-realm"
    )]
    idp_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArguments::parse();

    simple_logger::SimpleLogger::new()
        .with_level(
            args.log_level
                .log_level()
                .context("No log level given")?
                .to_level_filter(),
        )
        .with_utc_timestamps()
        .init()?;

    {
        let idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
            url::Url::parse(&args.idp_url)?,
        )
        .await?
        .set_default_idp_refresh_strategy()
        .await?;

        log::debug!("JWKS: {:?}", idp.jwks().await?);

        std::thread::sleep(std::time::Duration::new(65, 0));

        log::debug!("JWKS: {:?}", idp.jwks().await);
    }

    // std::thread::sleep(std::time::Duration::new(60, 0));

    Ok(())
}
