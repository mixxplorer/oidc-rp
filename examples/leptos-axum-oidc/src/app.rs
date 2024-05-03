use crate::error_template::{AppError, ErrorTemplate};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;
use oidc_rp::oidc::url;

const IDP_METADATA_URI: &str = "https://keycloak.example.org/realms/test";
const IDP_CLIENT_ID: &str = "leptos-axum-oidc";

static OIDC_IDP: std::sync::RwLock<
    Option<
        oidc_rp::idp::IdP<oidc_rp::idp::EmptyAdditionalIdPMetadata, oidc_rp::types::AttributeSet>,
    >,
> = std::sync::RwLock::new(None);

#[leptos::server(GetIdPMetadata, "/api")]
pub async fn get_idp_metadata() -> Result<oidc_rp::idp::IdPAttributesShare, leptos::ServerFnError> {
    if OIDC_IDP.read().unwrap().is_none() {
        let new_idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
            url::Url::parse(IDP_METADATA_URI).unwrap(),
        )
        .await
        .unwrap()
        .set_default_idp_refresh_strategy()
        .await
        .unwrap();
        let mut writable_oidc_idp = OIDC_IDP.write().unwrap();
        if writable_oidc_idp.is_none() {
            *writable_oidc_idp = Some(new_idp);
        }
    }

    let idp = {
        let idp_read = OIDC_IDP.read().unwrap();
        idp_read.as_ref().unwrap().clone()
    };

    Ok(idp.state().await?)
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    oidc_rp::integrations::leptos::ClientAuth::initialize(
        "/callback/oidc".to_string(),
        true,
        |cached_idp_attributes_option| async {
            let cached_idp_attributes = match cached_idp_attributes_option {
                Some(cached_idp_attributes) => cached_idp_attributes,
                None => get_idp_metadata().await.unwrap(),
                // without server function
                // None => {
                //     oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
                //         url::Url::parse(IDP_METADATA_URI).unwrap(),
                //     )
                //     .await?.state().await?
                // }
            };
            let oidc_idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::try_from(
                cached_idp_attributes,
            )?
            .set_default_idp_refresh_strategy()
            .await?;
            let client_id = IDP_CLIENT_ID.to_string();
            let verifier = oidc_rp::verifier::Verifier::new(oidc_idp.clone(), client_id.clone())
                .unwrap()
                .allow_all_access_token_jose_types()
                .set_other_audience_verifier_fn(|_| true);
            let oidc_account = oidc_rp::account::Account::new_public(oidc_idp, client_id, verifier);

            Ok(oidc_account)
        },
    );
    let auth = oidc_rp::integrations::leptos::ClientAuth::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::from_context();

    view! {
        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/leptos-axum-oidc.css"/>

        // sets the document title
        <Title text="Welcome to Leptos OIDC example"/>

        <Suspense fallback=move || view! { <p>"Loading"</p> }><p>{move || auth.resource.get().map(|_| "Loaded") }</p></Suspense>
        // <Show when=move || res.loading().get()>"SHOWtime!"</Show>

        // content for this welcome page
        <Router fallback=|| {
            let mut outside_errors = Errors::default();
            outside_errors.insert_with_default_key(AppError::NotFound);
            view! {
                <ErrorTemplate outside_errors/>
            }
            .into_view()
        }>
            <main>
                <Routes>
                    <Route path="callback/oidc" view=crate::callback::Oidc/>
                    <Route path="" view=HomePage/>
                    <Route path="oidc_example" view=crate::oidc_example::OidcExample/>
                </Routes>
            </main>
        </Router>
    }
}

/// Renders the home page of your application.
#[component]
fn HomePage() -> impl IntoView {
    // Creates a reactive value to update the button
    let (count, set_count) = create_signal(0);
    let on_click = move |_| set_count.update(|count| *count += 1);

    view! {
        <h1>"Welcome to Leptos!"</h1>
        <button on:click=on_click>"Click Me: " {count}</button>

        <p>"Go to "<a href="oidc_example">"OIDC example page"</a></p>
    }
}
