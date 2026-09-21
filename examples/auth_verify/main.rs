use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Verification example / benchmark")]
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
    let access_token: String = {
        let idp = oidc_rp::idp::IdP::new(url::Url::parse(&args.idp_url)?)
            .await?
            .set_no_idp_refresh_strategy()
            .await?;

        let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
            idp.clone(),
            args.client_id.clone(),
        )?
        .allow_all_access_token_jose_types()
        .allow_other_audiences();

        let account: oidc_rp::account::Account<
            _,
            _,
            oidc_rp::oidc::EmptyAdditionalProviderMetadata,
        > = oidc_rp::account::Account::from_public_client(idp, args.client_id.clone(), verifier);

        let account = account
            .exchange_password(args.username, args.password)
            .await?;

        tracing::info!("Account password exchanged for token");
        tracing::debug!("Access token: {:?}", account.get_access_token().await?);

        account.get_access_token().await?.clone()
    };

    tracing::debug!("Real AT: {access_token}");

    // now, verify this access token as we would be a relying party
    {
        let idp = oidc_rp::idp::IdP::<oidc_rp::oidc::EmptyAdditionalProviderMetadata>::new(
            url::Url::parse(&args.idp_url)?,
        )
        .await?
        .set_no_idp_refresh_strategy()
        .await?;

        let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
            idp,
            args.client_id,
        )?
        .allow_all_access_token_jose_types()
        .set_other_audience_verifier_fn(|_| true);
        tracing::info!("Starting verifying claims");
        // 10_000 is arbitrary such that all verifications should terminate on reasonable hardware before the token expires.
        for _ in 0..10_000 {
            verifier.verify_access_token(&access_token).await.unwrap();
        }
        tracing::info!("Verified 10k access tokens!");
        let claims: oidc_rp::verifier::JwtAccessTokenClaims<_> =
            verifier.verify_access_token(&access_token).await.unwrap();
        tracing::info!("Extracted claims!");
        tracing::debug!("Claims: {claims:#?}");

        // wait two minutes until access token becomes invalid (default for the Keycloak test setup)
        std::thread::sleep(std::time::Duration::new(120, 0));
        let expected_error = verifier.verify_access_token(&access_token).await;
        match expected_error {
            Ok(_) => anyhow::bail!("Access token validation should have errored!"),
            Err(error) => {
                tracing::info!("Access token validation has errored as expected!");
                tracing::debug!("Access token validation error: {error:?}");
            }
        }
    }

    Ok(())
}
