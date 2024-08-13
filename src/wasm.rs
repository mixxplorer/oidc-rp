const OIDC_RP_LOCAL_STORAGE_KEY: &str = "oidc-rp-auth";

/// Wasm Error type, which is clonable required for leptos integration
#[derive(thiserror::Error, Clone, Debug)]
pub enum WasmError {
    #[error("Module not ready (e.g. no metadata available)")]
    NotReady(String),

    #[error("IdP returned an error. Probably the JWKS cannot be fetched?")]
    IdPError(std::sync::Arc<crate::idp::IdPError>),

    #[error("Account object returned an error. Probably the token is invalid?")]
    AccountError(std::sync::Arc<crate::account::AccountError>),

    #[error("Authentication required!")]
    AuthenticationRequired(),

    #[error("Unable to verify token!")]
    VerificationError(#[from] openidconnect::ClaimsVerificationError),

    #[error("No IDP refresh strategy set!")]
    NoIdPDataRefreshStrategy(),

    #[error("Unable to retrieve a specific element via web-sys!")]
    WebSysElementError(String),

    #[error("Query Parameter is missing!")]
    QueryParamsMissing(String),

    #[error("Authentication state is missing! Re-Authentication required!")]
    AuthStateMissing(String),

    #[error("Invalid auth state found, please retry authentication.")]
    AuthStateInvalid(String),

    #[error("Generic JS error")]
    JsError(web_sys::wasm_bindgen::JsValue),

    #[error("Unable to parse URL")]
    UrlParseError(#[from] url::ParseError),

    #[error("Invalid URL")]
    InvalidUrl(String),

    #[error("Invalid redirect URI")]
    InvalidRedirectUri(String),
}

impl From<web_sys::wasm_bindgen::JsValue> for WasmError {
    fn from(value: web_sys::wasm_bindgen::JsValue) -> Self {
        Self::JsError(value)
    }
}

impl From<crate::account::AccountError> for WasmError {
    fn from(value: crate::account::AccountError) -> Self {
        Self::AccountError(std::sync::Arc::new(value))
    }
}

impl From<crate::idp::IdPError> for WasmError {
    fn from(value: crate::idp::IdPError) -> Self {
        Self::IdPError(std::sync::Arc::new(value))
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct LocalStorageAuthorizePkceStateStore {
    authorizations: std::collections::HashMap<String, LocalStorageAuthorizePkceStateStoreItem>,
}

impl LocalStorageAuthorizePkceStateStore {
    fn remove_expired_authorizations(mut self) -> Self {
        self.authorizations.retain(|_key, value| value.expiration > chrono::offset::Utc::now());
        self
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct LocalStorageAuthorizePkceStateStoreItem {
    state: crate::account::AuthorizePkceState,
    expiration: chrono::DateTime<chrono::offset::Utc>,
}

/// Gets access tokens provided by tokens via URL.
///
/// Call this after a user gets redirected back to the app after calling [`store_authorize_state`](`store_authorize_state`)
pub async fn exchange_pkce_token_from_url<APM>(
    account: crate::account::Account<APM, crate::types::AttributeNotSet>,
) -> Result<
    (
        crate::account::Account<APM, crate::types::AttributeSet>,
        url::Url,
    ),
    WasmError,
>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
{
    let window = web_sys::window().ok_or(WasmError::WebSysElementError(
        "Unable to retrieve window!".to_string(),
    ))?;
    let local_storage = window
        .local_storage()?
        .ok_or(WasmError::WebSysElementError(
            "Unable to retrieve local storage!".to_string(),
        ))?;
    let auth_json =
        local_storage
            .get_item(OIDC_RP_LOCAL_STORAGE_KEY)?
            .ok_or(WasmError::AuthStateMissing(
                "Local Storage state not accessible.".to_string(),
            ))?;
    let href = window.location().href()?;
    let url = url::Url::parse(&href)?;
    let mut auth_state_store =
        serde_json::from_str::<LocalStorageAuthorizePkceStateStore>(&auth_json)
            .map_err(|err| {
                WasmError::AuthStateInvalid(format!("Unable to parse stored auth state: {err:?}"))
            })?
            .remove_expired_authorizations();

    // parse CSRF / state value
    let csrf_token = url
        .query_pairs()
        .find(|(key, _value)| key == "state")
        .ok_or(WasmError::AuthStateMissing(
            "No state found in URL!".to_string(),
        ))?
        .1
        .to_string();

    // check for outdated entries
    let auth_state =
        auth_state_store
            .authorizations
            .remove(&csrf_token)
            .ok_or(WasmError::AuthStateMissing(
                "Element not found in stored auth states.".to_string(),
            ))?;

    // update store in local storage
    local_storage.set_item(
        OIDC_RP_LOCAL_STORAGE_KEY,
        &serde_json::to_string(&auth_state_store).unwrap(),
    )?;

    let (_, code) = url
        .query_pairs()
        .find(|(key, _value)| &*key == "code")
        .ok_or(WasmError::QueryParamsMissing("state".to_string()))?;

    let redirect_url = auth_state.state.redirect_url.clone();
    Ok((
        account
            .exchange_code_pkce(code.to_string(), auth_state.state)
            .await?
            .start_auto_refresh(),
        redirect_url,
    ))
}

/// Stores the PKCE authorize state to local storage to be retrieved when user is redirected back to the app.
///
/// See also [`exchange_pkce_token_from_url`](`exchange_pkce_token_from_url`)
pub fn store_authorize_state(state: crate::account::AuthorizePkceState) -> Result<(), WasmError> {
    let window = web_sys::window().ok_or(WasmError::WebSysElementError(
        "Unable to retrieve window!".to_string(),
    ))?;
    let local_storage = window
        .local_storage()?
        .ok_or(WasmError::WebSysElementError(
            "Unable to retrieve local storage!".to_string(),
        ))?;
    let auth_json_result =
        local_storage
            .get_item(OIDC_RP_LOCAL_STORAGE_KEY)?
            .ok_or(WasmError::AuthStateMissing(
                "Local Storage state not accessible.".to_string(),
            ));

    let mut auth_state_store = match auth_json_result {
        Ok(auth_json) => serde_json::from_str::<LocalStorageAuthorizePkceStateStore>(&auth_json)
            .unwrap_or(LocalStorageAuthorizePkceStateStore {
                authorizations: std::collections::HashMap::new(),
            }),
        Err(_) => Default::default(),
    }
    .remove_expired_authorizations();

    auth_state_store.authorizations.insert(
        state.csrf_token.secret().clone(),
        LocalStorageAuthorizePkceStateStoreItem {
            state,
            expiration: chrono::offset::Utc::now() + chrono::Duration::new(60 * 5, 0).unwrap(),
        },
    );

    local_storage.set_item(
        OIDC_RP_LOCAL_STORAGE_KEY,
        &serde_json::to_string(&auth_state_store).unwrap(),
    )?;

    Ok(())
}

/// Returns the current uri from window.
pub fn get_current_uri() -> Result<url::Url, WasmError> {
    let window = web_sys::window().ok_or(WasmError::WebSysElementError(
        "Unable to retrieve window!".to_string(),
    ))?;
    let location_href = window.location().href()?;
    Ok(url::Url::parse(&location_href)?)
}

/// Verifies redirect uri. Call this function before redirecting the user to prevent open redirects.
///
/// If you want to redirect the user directly to the url, please use [`verify_and_redirect_to_redirect_uri`].
pub fn verify_redirect_uri(redirect_uri: &url::Url) -> Result<(), WasmError> {
    verify_and_optionally_redirect_to_redirect_uri(redirect_uri, false)
}

/// Verifies redirect uri and then redirects the user to it (with skipping history). Call this function before redirecting the user to prevent open redirects.
///
/// If you do not want to redirect the user directly to the url, please use [`verify_redirect_uri`].
pub fn verify_and_redirect_to_redirect_uri(redirect_uri: &url::Url) -> Result<(), WasmError> {
    verify_and_optionally_redirect_to_redirect_uri(redirect_uri, true)
}

/// Internal function to provide [`verify_redirect_uri`] and  [`verify_and_redirect_to_redirect_uri`].
fn verify_and_optionally_redirect_to_redirect_uri(
    redirect_uri: &url::Url,
    redirect: bool,
) -> Result<(), WasmError> {
    let window = web_sys::window().ok_or(WasmError::WebSysElementError(
        "Unable to retrieve window!".to_string(),
    ))?;

    // verify whether uri is on our own host (so we are not imposing an open redirect)
    {
        let window_location_part = window.location().hostname()?;
        let redirect_uri_part = redirect_uri
            .host()
            .ok_or(WasmError::InvalidUrl(
                "No host part in redirect_uri".to_string(),
            ))?
            .to_string();
        if window_location_part != redirect_uri_part {
            return Err(WasmError::InvalidRedirectUri(format!(
                "Host location '{}' != '{}'",
                window_location_part, redirect_uri_part
            )));
        }
    }
    {
        let window_location_part = window.location().port()?;
        let redirect_uri_part = redirect_uri
            .port_or_known_default()
            .ok_or(WasmError::InvalidUrl(
                "No host part in redirect_uri".to_string(),
            ))?
            .to_string();
        if window_location_part != redirect_uri_part {
            return Err(WasmError::InvalidRedirectUri(format!(
                "Host port '{}' != '{}'",
                window_location_part, redirect_uri_part
            )));
        }
    }
    {
        let window_location_part = window.location().protocol()?;
        let redirect_uri_part = format!("{}:", redirect_uri.scheme()); // see https://developer.mozilla.org/en-US/docs/Web/API/Location/protocol
        if window_location_part != redirect_uri_part {
            return Err(WasmError::InvalidRedirectUri(format!(
                "Host protocol '{}' != '{}'",
                window_location_part, redirect_uri_part
            )));
        }
    }

    if redirect {
        window.location().replace(redirect_uri.as_str())?;
    }

    Ok(())
}
