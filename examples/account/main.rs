use anyhow::Context;
use clap::Parser;

/// Example of a CLI application that autheticates to an IDP using the deprecated implicit flow.
/// It then proceeds to resfresh the access token as required and prints the tokens.
/// Due to openidconnect-rs, the audience must match the client_id.

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Account example")]
pub struct CliArguments {
    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity,

    #[arg(short, long, help = "Username to use for direct grant authentication")]
    username: String,
    #[arg(short, long, help = "Password to use for direct grant authentication")]
    password: String,

    #[arg(
        short,
        long,
        help = "Base URL of IdP, e.g. https://keycloak.example.org/realms/your-realm"
    )]
    idp_url: String,

    #[arg(short, long, help = "Client id at your IdP", default_value = "oidc-rp")]
    client_id: String,
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

    // fetch access token as we would be a cli tool

    let idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(url::Url::parse(
        &args.idp_url,
    )?)
    .await?
    .set_default_idp_refresh_strategy()
    .await?;

    let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
        idp.clone(),
        args.client_id.clone(),
    )?
    .allow_all_access_token_jose_types()
    .set_other_audience_verifier_fn(|_| true);
    let account: oidc_rp::account::Account<_, _, oidc_rp::oidc::EmptyAdditionalProviderMetadata> =
        oidc_rp::account::Account::new_public(idp, args.client_id.clone(), verifier);

    let account = account
        .exchange_password(args.username, args.password, vec!["openid".to_string()])
        .await?;
    let account = account.start_auto_refresh();

    loop {
        log::info!("Access token: {:?}", account.get_access_token().await?);
        log::info!("ID token claims: {:?}", account.get_id_token_claims().await);

        std::thread::sleep(std::time::Duration::new(90, 0));
    }
}
