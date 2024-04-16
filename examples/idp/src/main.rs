use anyhow::Context;
use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version,
    long_about = "Brownie shutdown hook implementation. To be called during shutdown."
)]
pub struct CliArguments {
    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity,
}

fn main() -> anyhow::Result<()> {
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
        let mut idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
            url::Url::parse("https://keycloak.giz.berlin/auth/realms/giz-playground")?,
        )?;
        idp.set_default_jwks_refresh_strategy()?;

        log::debug!("JWKS: {:?}", idp.jwks());

        std::thread::sleep(std::time::Duration::new(65, 0));

        log::debug!("JWKS: {:?}", idp.jwks());
    }

    std::thread::sleep(std::time::Duration::new(60, 0));

    Ok(())
}
