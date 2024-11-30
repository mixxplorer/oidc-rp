use anyhow::Context;
use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Verification example / benchmark")]
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
    let access_token: String = {
        let idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
            url::Url::parse(&args.idp_url)?,
        )
        .await?
        .set_no_idp_refresh_strategy()
        .await?;

        let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
            idp.clone(),
            args.client_id.clone(),
        )?
        .allow_all_access_token_jose_types()
        .set_other_audience_verifier_fn(|_| true);
        let account: oidc_rp::account::Account<oidc_rp::oidc::EmptyAdditionalProviderMetadata, _> =
            oidc_rp::account::Account::new_public(idp, args.client_id.clone(), verifier);

        let account = account
            .exchange_password(args.username, args.password)
            .await?;

        log::info!("Access token: {:?}", account.get_access_token().await?);

        account.get_access_token().await?.clone()
    };

    log::debug!("Real AT: {access_token}");

    // now, verify this access token as we would be a relying party
    {
        let idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
            url::Url::parse(&args.idp_url)?,
        )
        .await?
        .set_default_idp_refresh_strategy()
        .await?;

        let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
            idp,
            args.client_id,
        )?
        .allow_all_access_token_jose_types()
        .set_other_audience_verifier_fn(|_| true);
        log::info!("Starting verifying claims");

        // 10_000 is arbitrary such that all verifications should terminate on reasonable hardware before the token expires.
        for i in 0..10_000 {
            verifier
                .verify_access_token(&access_token)
                .await
                .expect(format!("Iteration: {}", i).as_str());
        }
        log::info!("Verified 10k access tokens!");
        let claims: oidc_rp::verifier::JwtAccessTokenClaims<oidc_rp::oidc::EmptyAdditionalClaims> =
            verifier.verify_access_token(&access_token).await.unwrap();
        log::info!("Verified! Claims: {claims:#?}");
    }

    Ok(())
}
