//! Example of a CLI application that uses the Keycloak token supplier.

use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(author, version, long_about = "Keycloak example")]
pub struct CliArguments {
    #[clap(flatten)]
    verbosity: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,

    #[arg(long, help = "Client id at your IdP", default_value = "oidc-rp")]
    client_id: String,
    #[arg(
        long,
        help = "Client secret of the client id",
        default_value = "notSecureAtAllTest"
    )]
    client_secret: String,

    #[arg(long, help = "Realm to use", default_value = "oidc-rp")]
    realm: String,

    #[arg(
        long,
        help = "Base URL of Keycloak, e.g. https://keycloak.example.org/",
        default_value = "http://keycloak.internal/"
    )]
    keycloak_base_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArguments::parse();
    let token_retriever_http_client = oidc_rp::reqwest_client::get_default_reqwest_client()
        .danger_accept_invalid_certs(true) // Enable for this example.
        .build()
        .unwrap();
    let keycloak_client = oidc_rp::integration::keycloak::TokenSupplier::new_with_reqwest_client(
        &args.client_id,
        &args.client_secret,
        &args.realm,
        args.keycloak_base_url.as_str(),
        token_retriever_http_client,
    )
    .await?;
    let api_http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Enable for this example.
        .build()
        .unwrap();

    let keycloak_admin =
        keycloak::KeycloakAdmin::new(&args.keycloak_base_url, keycloak_client, api_http_client);

    let users: keycloak::types::TypeVec<keycloak::types::UserRepresentation> =
        keycloak_admin.realm(&args.realm).users_get().await?;
    let count: i32 = keycloak_admin.realm(&args.realm).users_count_get().await?;
    let count: usize = count.try_into()?;
    assert_eq!(users.len(), count);
    Ok(())
}
