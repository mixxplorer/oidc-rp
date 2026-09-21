use clap::Parser;

mod errors;
mod handlers;
mod util;

#[derive(Clone)]
struct AppState {
    idp: oidc_rp::idp::IdP<
        openidconnect::EmptyAdditionalProviderMetadata,
        oidc_rp::types::AttributeSet,
    >,
}

impl AppState {
    fn new(
        idp: oidc_rp::idp::IdP<
            openidconnect::EmptyAdditionalProviderMetadata,
            oidc_rp::types::AttributeSet,
        >,
    ) -> anyhow::Result<AppState> {
        Ok(AppState { idp })
    }
}

unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

impl
    oidc_rp::integration::axum::IdPProvider<
        openidconnect::EmptyAdditionalClaims,
        openidconnect::EmptyAdditionalClaims,
        openidconnect::EmptyAdditionalProviderMetadata,
    > for AppState
{
    fn get_oidc_rp_verifier(
        &self,
    ) -> oidc_rp::verifier::Verifier<
        openidconnect::EmptyAdditionalClaims,
        openidconnect::EmptyAdditionalClaims,
        openidconnect::EmptyAdditionalProviderMetadata,
    > {
        let verifier = oidc_rp::verifier::Verifier::new(self.idp.clone(), "test".to_owned())
            .unwrap()
            .allow_all_access_token_jose_types()
            .set_other_audience_verifier_fn(|_| true);
        verifier
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = "Exposes an example web API")]
pub struct CliArguments {
    #[clap(
        long,
        short,
        default_value = "[::1]:3000",
        help = "Bind address with port, e.g. [::1]:3000"
    )]
    bind_addr: String,

    #[arg(
        short,
        long,
        help = "Base URL of IdP, e.g. https://keycloak.example.org/realms/your-realm",
        default_value = "http://keycloak.internal/realms/oidc-rp"
    )]
    idp_url: String,

    #[clap(flatten)]
    verbosity: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

async fn serve_api(
    axum::Extension(api): axum::Extension<aide::openapi::OpenApi>,
) -> impl aide::axum::IntoApiResponse {
    axum::Json(api)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArguments::parse();

    tracing_subscriber::fmt()
        .with_max_level(args.verbosity)
        .init();

    // see https://robertying.com/post/sigterm-docker/ for an explanation why this is necessary
    ctrlc::set_handler(move || {
        tracing::info!("received Ctrl+C! Exiting!");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let idp = oidc_rp::idp::IdP::<oidc_rp::oidc::EmptyAdditionalProviderMetadata>::new(
        url::Url::parse(&args.idp_url)?,
    )
    .await?
    .set_no_idp_refresh_strategy()
    .await?;

    tracing::info!("Constructing app state...");
    let state = AppState::new(idp)?;
    tracing::info!("Done constructing app state!");

    // create metadata for API docs
    let mut api = aide::openapi::OpenApi {
        info: aide::openapi::Info {
            title: "OIDC RP Axum example API".to_string(),
            description: Some("Just a little API to demo some features".to_string()),
            contact: Some(aide::openapi::Contact {
                name: Some("Leonard Marschke".to_string()),
                url: Some("https://rechenknecht.net/mixxplorer/libraries/oidc-rp".to_string()),
                email: Some("leo@mixxplorer.de".to_string()),
                extensions: indexmap::IndexMap::new(),
            }),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..aide::openapi::Info::default()
        },
        ..aide::openapi::OpenApi::default()
    };

    let authenticated_router = aide::axum::ApiRouter::new()
        .api_route(
            "/test",
            aide::axum::routing::post_with(handlers::authenticated, handlers::authenticated_desc),
        )
        .route_layer(oidc_rp::integration::axum::OIDCAuthenticationLayer::new(
            state.clone(),
        ));

    // build our application utilizing the ApiRouter from aide, allowing to automatically add doc
    let app = aide::axum::ApiRouter::new()
        // Add routes of official API
        .api_route(
            "/v1/health",
            aide::axum::routing::get_with(handlers::health, handlers::health_desc),
        )
        .api_route(
            "/v1/authenticated/test",
            aide::axum::routing::post_with(handlers::authenticated, handlers::authenticated_desc),
        )
        // Add non-documented routes (e.g. displaying the docs)
        .route("/docs/api.json", aide::axum::routing::get(serve_api))
        .route(
            "/docs",
            aide::redoc::Redoc::new("/docs/api.json")
                .with_title("LCC API")
                .axum_route(),
        )
        .route(
            "/",
            aide::axum::routing::get(|| async { axum::response::Redirect::to("/docs") }),
        )
        // Add global API state
        .with_state(state)
        // Finish building the API
        .finish_api(&mut api)
        // Add aide (open API) extension layer
        .layer(axum::Extension(api))
        .into_make_service();

    // run our app
    let listener = tokio::net::TcpListener::bind(args.bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
