use clap::Parser;

/// Example of a CLI application that autheticates to an IDP using the deprecated implicit flow.
/// It then proceeds to resfresh the access token as required and prints the tokens.
/// Due to openidconnect-rs, the audience must match the client_id.

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Account example")]
pub struct CliArguments {
    #[clap(flatten)]
    verbosity: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,

    #[arg(
        short,
        long,
        help = "Username to use for direct grant authentication",
        default_value = "test"
    )]
    username: String,
    #[arg(
        short,
        long,
        help = "Password to use for direct grant authentication",
        default_value = "notSecureAtAllTest"
    )]
    password: String,

    #[arg(
        short,
        long,
        help = "Base URL of IdP, e.g. https://keycloak.example.org/realms/your-realm",
        default_value = "http://keycloak.internal/realms/oidc-rp"
    )]
    idp_url: String,

    #[arg(short, long, help = "Client id at your IdP", default_value = "oidc-rp")]
    client_id: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArguments::parse();

    tracing_subscriber::fmt()
        .with_max_level(args.verbosity)
        .init();

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
        oidc_rp::account::Account::from_public_client(idp, args.client_id.clone(), verifier);

    let account = account
        .exchange_password(args.username, args.password, vec!["openid".to_string()])
        .await?;
    let account = account.start_auto_refresh();

    let first_at = account.get_access_token().await?;
    tracing::info!("First Access Token: {:?}", first_at);
    tracing::debug!("ID token claims: {:?}", account.get_id_token_claims().await);

    std::thread::sleep(std::time::Duration::new(70, 0));

    // With our test setup (Keycloak) where access tokens expire every 2 minutes, we expect to see the same token
    if first_at == account.get_access_token().await? {
        tracing::info!("Still getting same access token as expected!");
    } else {
        anyhow::bail!("Access token has unexpectedly changed!");
    }

    std::thread::sleep(std::time::Duration::new(120 - 70, 0));

    let final_at = account.get_access_token().await?;
    if final_at == first_at {
        anyhow::bail!("first and final access tokens are equal, although they should not be!")
    }

    tracing::info!("New access token has been fetched.");
    tracing::debug!("Access token: {:?}", final_at);
    // ensure id token claims can still be fetched
    tracing::debug!("ID token claims: {:?}", account.get_id_token_claims().await);

    Ok(())
}
