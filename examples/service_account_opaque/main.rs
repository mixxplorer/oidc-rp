use clap::Parser;

/// Example of a CLI application that autheticates to an IDP using a service account.
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
        help = "Base URL of IdP, e.g. https://keycloak.example.org/realms/your-realm",
        default_value = "http://keycloak.internal/realms/oidc-rp"
    )]
    idp_url: String,

    #[arg(long, help = "Client id at your IdP", default_value = "oidc-rp-secret")]
    client_id: String,

    #[arg(
        short,
        long,
        help = "Secret to use for client credentials grant authentication",
        default_value = "m7moK8yJJbqKYyIULCX356aJR6hJ5XIvZMAuyP1YN4QLqEOOzjYXBH50j6cn9A28irAwHtRFAHKpYEg9Up1GV7"
    )]
    client_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArguments::parse();

    tracing_subscriber::fmt()
        .with_max_level(args.verbosity)
        .init();

    let idp = oidc_rp::idp::IdP::new(url::Url::parse(&args.idp_url)?)
        .await?
        .set_default_idp_refresh_strategy()
        .await?;

    let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
        idp.clone(),
        args.client_id.clone(),
    )?
    .set_access_token_allowed_jose_types(vec![
        openidconnect::JsonWebTokenType::new("JWT".to_owned()).normalize()?,
    ])
    .allow_other_audiences();
    let account: oidc_rp::account::Account<
        _,
        _,
        _,
        oidc_rp::account::access_token_type::Opaque,
        oidc_rp::account::account_user_type::ServiceAccount,
        oidc_rp::types::AttributeSet,
    > = oidc_rp::account::Account::from_secret_client(
        idp,
        args.client_id.clone(),
        args.client_secret.clone(),
        verifier,
    );

    let account = account
        .exchange_client_credentials(vec!["openid".to_owned()])
        .await?
        .start_auto_refresh();

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
