use std::io::BufRead;

use anyhow::Context;
use clap::Parser;

/// Example of generating and receiving a PKCE flow
/// You must be able to access `keycloak.internal` via your browser for this example.
/// You could achieve this by e.g. binding the Keycloak docker container IP address to `keycloak.internal` via `/etc/hosts`.

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Account example")]
pub struct CliArguments {
    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,

    #[arg(
        short,
        long,
        help = "Base URL of IdP, e.g. https://keycloak.example.org/realms/your-realm",
        default_value = "http://keycloak.internal/realms/oidc-rp"
    )]
    idp_url: String,

    #[arg(
        short,
        long,
        help = "Client id at your IdP",
        default_value = "oidc-rp-pkce"
    )]
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

    let idp = oidc_rp::idp::IdP::new(url::Url::parse(&args.idp_url)?)
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

    let (pkce_url, pkce_state) = account
        .authorize_url_pkce(
            vec![],
            url::Url::parse("http://nonexistant.internal")?,
            None,
        )
        .await?;

    println!("Please go to {pkce_url} in your browser, then copy over the 'code' parameter.");

    print!("Code query parameter: ");
    let stdin = std::io::stdin();
    let mut stdin_iterator = stdin.lock().lines();
    let code_query_param = stdin_iterator.next().expect("No query parameter passed")?;
    let account = account
        .exchange_code_pkce(code_query_param, pkce_state)
        .await?
        .0;

    let first_at = account.get_access_token().await?;
    log::info!("First Access Token: {:?}", first_at);
    log::debug!("ID token claims: {:?}", account.get_id_token_claims().await);

    Ok(())
}
