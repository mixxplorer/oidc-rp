use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Automatic JWKS reload example")]
pub struct CliArguments {
    #[clap(flatten)]
    verbosity: clap_verbosity_flag::Verbosity,

    #[arg(
        short,
        long,
        help = "Base URL of IdP, e.g. https://keycloak.example.org/realms/your-realm",
        default_value = "http://keycloak.internal/realms/oidc-rp"
    )]
    idp_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArguments::parse();

    tracing_subscriber::fmt()
        .with_max_level(args.verbosity)
        .init();

    {
        let idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
            url::Url::parse(&args.idp_url)?,
        )
        .await?
        .set_default_idp_refresh_strategy()
        .await?;

        let jwks = idp.jwks().await?;
        tracing::info!("Received JWKS!");
        tracing::debug!("JWKS: {:?}", jwks);

        std::thread::sleep(std::time::Duration::new(65, 0));

        let jwks = idp.jwks().await?;
        tracing::info!("Received JWKS!");
        tracing::debug!("JWKS: {:?}", jwks);
    }

    Ok(())
}
