//! Module for creating an OIDC account providing tokens.
//! Featuring automatic refresh of those tokens if desired.
//!
//! See [`Account`] for usage entrypoint.

use openidconnect::{OAuth2TokenResponse, TokenResponse};

#[derive(thiserror::Error, Debug)]
pub enum AccountError {
    #[error("Configuration invalid.")]
    ConfigurationError(#[from] openidconnect::ConfigurationError),

    #[error("Unable to fetch data from IdP.")]
    FetchError(
        #[from]
        openidconnect::RequestTokenError<
            openidconnect::HttpClientError<reqwest::Error>,
            openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
        >,
    ),

    #[error("Next refresh is in past!")]
    NextRefreshFuture(#[from] std::time::SystemTimeError),

    #[error("Token too old. Refresh might have failed.")]
    TokenTooOld(),

    #[error("IdP returned an error. Probably the JWKS cannot be fetched?")]
    IdPError(#[from] crate::idp::IdPError),

    #[error("No Account tokens present, please fetch them before getting tokens.")]
    NoAccountTokensPresent(),

    #[error("Generic serde error!")]
    SerdeError(#[from] serde_json::Error),

    #[error("Access token verifier errored!")]
    VerifierError(#[from] crate::verifier::VerifierError),

    #[error("No Refresh token present!")]
    NoRefreshtoken(),
}

/// Holder for different access token types handled by [`Account`].
pub mod access_token_type {
    mod private {
        /// Private trait, see https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
        pub trait AttributeSealedState {}
    }

    pub trait AccessTokenType:
        private::AttributeSealedState + Send + Sync + Clone + serde::de::DeserializeOwned
    {
        /// Handle access token, verify if possible, parse metadata like expiry time.
        fn handle<AC, IC, APM>(
            verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,
            access_token: &str,
            expected_access_token_hash: Option<openidconnect::AccessTokenHash>,
            token_response_expires_in: Option<std::time::Duration>,
        ) -> impl std::future::Future<
            Output = Result<chrono::DateTime<chrono::Utc>, super::AccountError>,
        > + Send
        where
            AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static;
    }

    /// Tokens can be verified and decrypted by utilizing the [RFC9068](https://datatracker.ietf.org/doc/html/rfc9068).
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct JWT;
    impl AccessTokenType for JWT {
        async fn handle<AC, IC, APM>(
            verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,
            access_token: &str,
            expected_access_token_hash: Option<openidconnect::AccessTokenHash>,
            token_response_expires_in_opt: Option<std::time::Duration>,
        ) -> Result<chrono::DateTime<chrono::Utc>, super::AccountError>
        where
            AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
        {
            // get access token expiry and verify hash match
            let access_token_claims = verifier
                .verify_access_token_with_hash(access_token, expected_access_token_hash)
                .await?;
            let access_token_expiry = access_token_claims.expiration();

            if let Some(token_response_expires_in) = token_response_expires_in_opt {
                let current_time = chrono::Utc::now();
                let token_expiry_calculated = current_time + token_response_expires_in;
                let diff = token_expiry_calculated - access_token_expiry;
                tracing::trace!(
                    "Time difference between access token and token response is: {:?}",
                    diff
                );
                // This is an arbitrary chosen value, which should never become an issue.
                if diff > chrono::Duration::minutes(1) {
                    return Err(crate::verifier::VerifierError::AccessTokenTimeMismatch(
                        token_expiry_calculated,
                        access_token_expiry,
                    )
                    .into());
                }
            }

            Ok(access_token_expiry)
        }
    }
    impl private::AttributeSealedState for JWT {}

    /// Opaque tokens, access tokens cannot be read by client.
    ///
    /// This can be used when e.g.:
    ///
    /// * Tokens are opaque and only the IdP can verify them
    /// * Tokens are encrypted and this instacne does not have the keys
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Opaque;
    impl AccessTokenType for Opaque {
        async fn handle<AC, IC, APM>(
            _verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,
            _access_token: &str,
            _expected_access_token_hash: Option<openidconnect::AccessTokenHash>,
            token_response_expires_in_opt: Option<std::time::Duration>,
        ) -> Result<chrono::DateTime<chrono::Utc>, super::AccountError>
        where
            AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
        {
            // Access token is opaque, so we cannot verify anything here, but check that we have an expiry value
            if let Some(token_response_expires_in) = token_response_expires_in_opt {
                let current_time = chrono::Utc::now();
                let token_expiry_calculated = current_time + token_response_expires_in;
                return Ok(token_expiry_calculated);
            }
            Err(crate::verifier::VerifierError::AccessTokenNoExpiryTime().into())
        }
    }
    impl private::AttributeSealedState for Opaque {}
}

/// Holder for different account user types handled by [`Account`].
pub mod account_user_type {
    mod private {
        /// Private trait, see https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
        pub trait AttributeSealedState {}
    }

    pub trait AccountUserType:
        private::AttributeSealedState + Send + Sync + Clone + serde::de::DeserializeOwned
    {
        fn get_updater<AC, IC, APM, ATT, AUT>(
            idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
            account_tokens: std::sync::Arc<tokio::sync::RwLock<super::AccountTokens<IC>>>,
            client_id: openidconnect::ClientId,
            client_secret: Option<openidconnect::ClientSecret>,
            min_validity_access_token_target: std::sync::Arc<chrono::TimeDelta>,
            verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,
        ) -> crate::updater::Updater<super::AccountError>
        where
            AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
            ATT: super::access_token_type::AccessTokenType + 'static,
            AUT: AccountUserType;
    }

    /// Normal user accounts.
    ///
    /// For tokens fetched via default token exchange mechanisms where user credentials cannot be re-presented.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct User;
    impl AccountUserType for User {
        fn get_updater<AC, IC, APM, ATT, AUT>(
            idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
            account_tokens: std::sync::Arc<tokio::sync::RwLock<super::AccountTokens<IC>>>,
            client_id: openidconnect::ClientId,
            client_secret: Option<openidconnect::ClientSecret>,
            min_validity_access_token_target: std::sync::Arc<chrono::TimeDelta>,
            verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,
        ) -> crate::updater::Updater<super::AccountError>
        where
            AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            APM: openidconnect::AdditionalProviderMetadata + Send + Sync + PartialEq + 'static,
            ATT: super::access_token_type::AccessTokenType + 'static,
        {
            let updater_impl: super::UpdaterImpl<AC, IC, APM, ATT, User> = super::UpdaterImpl {
                idp,
                account_tokens,
                client_id,
                client_secret,
                min_validity_access_token_target,
                verifier,
                access_token_type: std::marker::PhantomData::<ATT>,
                account_user_type: std::marker::PhantomData::<User>,
            };

            crate::updater::Updater::new(updater_impl)
        }
    }
    impl private::AttributeSealedState for User {}

    /// Account type for service accounts.
    ///
    /// These can be obtained e.g. by using the Client Credentials Grant.
    ///
    /// As there is no guarantee about refresh tokens, the updater needs to re-exchange the client credentials instead
    /// for some IdPs or depending on IdP configuration. See <https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3>.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct ServiceAccount;
    impl AccountUserType for ServiceAccount {
        fn get_updater<AC, IC, APM, ATT, AUT>(
            idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
            account_tokens: std::sync::Arc<tokio::sync::RwLock<super::AccountTokens<IC>>>,
            client_id: openidconnect::ClientId,
            client_secret: Option<openidconnect::ClientSecret>,
            min_validity_access_token_target: std::sync::Arc<chrono::TimeDelta>,
            verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,
        ) -> crate::updater::Updater<super::AccountError>
        where
            AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
            APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
            ATT: super::access_token_type::AccessTokenType + 'static,
            AUT: AccountUserType,
        {
            let updater_impl: super::UpdaterImpl<AC, IC, APM, ATT, ServiceAccount> =
                super::UpdaterImpl {
                    idp,
                    account_tokens,
                    client_id,
                    client_secret,
                    min_validity_access_token_target,
                    verifier,
                    access_token_type: std::marker::PhantomData::<ATT>,
                    account_user_type: std::marker::PhantomData::<ServiceAccount>,
                };

            crate::updater::Updater::new(updater_impl)
        }
    }
    impl private::AttributeSealedState for ServiceAccount {}
}

#[derive(Clone, Debug)]
pub struct AccountTokens<IC>
where
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
{
    refresh_token: Option<String>,
    /// The access token is stored as string as it should be handled as opaque by clients.
    /// If we would only store the parsed variant, the access token might loose some information not configured to parse in this lib, leading to incalid tokens.
    access_token: String,
    /// Store access token expiry date to not parse access token every time.
    access_token_expiry: chrono::DateTime<chrono::Utc>,
    id_token_claims: Option<openidconnect::IdTokenClaims<IC, openidconnect::core::CoreGenderClaim>>,
}

/// Must be saved when losing all state
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuthorizePkceState {
    pub pkce_verifier: openidconnect::PkceCodeVerifier,
    pub csrf_token: openidconnect::CsrfToken,
    pub nonce: openidconnect::Nonce,
    pub callback_url: url::Url,
    pub redirect_url: Option<url::Url>,
}

/// An OIDC Account, holding and managing tokens.
///
/// This object provides helpers to:
///
/// * Exchange user credentials for a token (including PKCE)
///     * [`PKCE URL generation`](`Account::authorize_url_pkce`) and [`PKCE code exchange`](`Account::exchange_code_pkce`)
///     * [`Client credentials grant`](`Account::exchange_client_credentials`)
///     * [`Direct grant / Resource Owner Password Credentials`](`Account::exchange_password`)
/// * Allows feeding in tokens fetched via other means and updating (and verifying) them
///     * [`Refresh token`](`Account::exchange_refresh_token`)
/// * Usage of public and secret clients
///     * [`Public clients`](`Account::from_public_client`)
///     * [`Secret clients`](`Account::from_secret_client`)
/// * Support of verifiable and opaque access tokens
///     * Verifiable: Pass [`access_token_type::JWT`] as `ATT`
///     * Opaque: Pass [`access_token_type::Opaque`] as `ATT`
/// * Support of different account types:
///     * Normal user accounts: Pass [`account_user_type::User`] as `AUT`
///     * Service accounts: Pass [`account_user_type::ServiceAccount`] as `AUT` (supports non-refresh-token refresh)
/// * Support additional claims in Access token (`AC`) and Identity token (`IC`), use [`openidconnect::AdditionalClaims`] to implement your own\
/// * Retrieve additional provider metadata (`APM`) via [`openidconnect::AdditionalProviderMetadata`]
///
/// Usage:
///
/// First, create an [Idp](`crate::idp::IdP`) and [Verifier](`crate::verifier::Verifier`) like
///
/// ```rust
/// # async fn test() -> anyhow::Result<()> {
/// # let client_id = "oidc-rp".to_owned();
/// # let idp_url = "http://keycloak.internal/realms/oidc-rp";
/// let idp = oidc_rp::idp::IdP::new(url::Url::parse(idp_url)?)
///    .await?
///    .set_default_idp_refresh_strategy()
///    .await?;
///
/// let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
///     idp,
///     client_id,
/// )?;
/// # Ok(())
/// # }
/// # tokio_test::block_on(async {
/// #    test().await.unwrap();
/// # })
/// ```
///
/// PKCE example (see also our full PKCE example at <../examples/pkce>):
///
/// ```rust
/// # async fn test() -> anyhow::Result<()> {
/// # let client_id = "oidc-rp".to_owned();
/// # let idp_url = "http://keycloak.internal/realms/oidc-rp";
/// let idp = oidc_rp::idp::IdP::new(url::Url::parse(idp_url)?)
///     .await?
///     .set_default_idp_refresh_strategy()
///     .await?;
///
/// let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
///     idp.clone(),
///     client_id.clone(),
/// )?;
///
/// let account: oidc_rp::account::Account = oidc_rp::account::Account::from_public_client(idp, client_id, verifier);
///
/// let (pkce_url, pkce_state) = account
///     .authorize_url_pkce(
///         vec![],
///         url::Url::parse("https://your-domain.example/callback")?,
///         None,
///     )
///     .await?;
///
/// // Now, a returned code can be exchanged and verified by the followding code:
/// // let code_query_param = ...get "code" query parameter;
/// // let account = account
/// //   .exchange_code_pkce(code_query_param, pkce_state)
/// //   .await?
/// //    account;
///
/// # Ok(())
/// # }
/// # tokio_test::block_on(async {
/// #    test().await.unwrap();
/// # })
/// ```
///
/// Client credentials grant (see also `../example/service_account_opaque`):
///
/// ```rust
/// # async fn test() -> anyhow::Result<()> {
/// # let client_id = "oidc-rp-secret".to_owned();
/// # let client_secret = "m7moK8yJJbqKYyIULCX356aJR6hJ5XIvZMAuyP1YN4QLqEOOzjYXBH50j6cn9A28irAwHtRFAHKpYEg9Up1GV7".to_owned();
/// # let idp_url = "http://keycloak.internal/realms/oidc-rp";
/// let idp = oidc_rp::idp::IdP::new(url::Url::parse(idp_url)?)
///     .await?
///     .set_default_idp_refresh_strategy()
///     .await?;
///
/// let verifier = oidc_rp::verifier::Verifier::<oidc_rp::oidc::EmptyAdditionalClaims>::new(
///         idp.clone(),
///         client_id.clone(),
///     )?
///     .set_access_token_allowed_jose_types(vec![openidconnect::JsonWebTokenType::new("JWT".to_owned()).normalize()?])
///     // Safe to do as it only allows other, additional audiences in token, our own audience will still be checked. Also, we trust the IdP.
///     .allow_other_audiences();
///
/// let account: oidc_rp::account::Account<
///        _, // no additional claims in access token
///        _, // no additional claims in id token
///        _, // no additional IdP metadata
///        oidc_rp::account::access_token_type::JWT, // default (JWT) token, will be verified before used
///        oidc_rp::account::account_user_type::ServiceAccount, // Account type is ServiceAccount here as the IdP might not provide a refresh token
///        oidc_rp::types::AttributeSet, // It is a secret client
///    > = oidc_rp::account::Account::from_secret_client(
///        idp,
///        client_id,
///        client_secret,
///        verifier,
///    );
///
///
/// // Important: This is becoming a diffferent object here, with different generics, therefore
/// // this must be a new variable. Only after `exchange_client_credentials` starting auto
/// // refresh is possible (the compiler enforces this thanks to rust typestates).
/// let account = account
///    .exchange_client_credentials(vec!["openid".to_owned()])
///    .await?
///    .start_auto_refresh();
///
/// // Access token can only be accessed **after** selecting a refresh strategy.
/// let access_token = account.get_access_token().await?;
///
/// # Ok(())
/// # }
/// # tokio_test::block_on(async {
/// #    test().await.unwrap();
/// # })
/// ```
#[derive(Debug, Clone)]
pub struct Account<
    AC = openidconnect::EmptyAdditionalClaims,
    IC = openidconnect::EmptyAdditionalClaims,
    APM = crate::idp::EmptyAdditionalIdPMetadata,
    ATT = access_token_type::JWT,
    AUT = account_user_type::User,
    IsConfidentialClient = crate::types::AttributeNotSet,
    AreAccountTokenAvailable = crate::types::AttributeNotSet,
> where
    APM: openidconnect::AdditionalProviderMetadata
        + PartialEq
        + Send
        + Sync
        + serde::de::DeserializeOwned,
    AreAccountTokenAvailable: crate::types::AttributeState + serde::de::DeserializeOwned,
    IsConfidentialClient: crate::types::AttributeState + serde::de::DeserializeOwned,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType,
    AUT: account_user_type::AccountUserType,
{
    idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
    client_id: openidconnect::ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    account_tokens: Option<std::sync::Arc<tokio::sync::RwLock<AccountTokens<IC>>>>,

    /// Minimum time an access token should still be valid for
    /// when returned from get_access_token and get_access_token_blocking
    ///
    /// This is to ensure to receive a TokenError when not enough time
    /// would be left to use the token.
    ///
    /// Default: 5 seconds.
    min_validity_access_token: std::sync::Arc<chrono::Duration>,

    /// Minimum time an access token should still be valid for
    /// when initiating a refresh.
    ///
    /// This should be larger than min_validity_access_token to ensure there
    /// is always a valid access token available, even if the request to refresh
    /// the token takes a little time.
    ///
    /// Default: 30 seconds.
    min_validity_access_token_target: std::sync::Arc<chrono::Duration>,
    min_validity_id_token: std::sync::Arc<chrono::Duration>,
    updater: Option<std::sync::Arc<crate::updater::Updater<AccountError>>>,
    verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,

    access_token_type: std::marker::PhantomData<ATT>,
    account_user_type: std::marker::PhantomData<AUT>,
    state_token_avail: std::marker::PhantomData<AreAccountTokenAvailable>,
    state_confidential_client: std::marker::PhantomData<IsConfidentialClient>,
}

impl<AC, IC, APM, ATT, AUT>
    Account<AC, IC, APM, ATT, AUT, crate::types::AttributeNotSet, crate::types::AttributeNotSet>
where
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType,
    AUT: account_user_type::AccountUserType,
{
    /// Creates a new Account object for a specific public client.
    ///
    /// See <htps://datatracker.ietf.org/doc/html/rfc6749#section-2.1> for more details.
    pub fn from_public_client(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: String,
        verifier: crate::verifier::Verifier<AC, IC, APM>,
    ) -> Self {
        Self {
            idp: idp.into(),
            client_id: openidconnect::ClientId::new(client_id),
            client_secret: None,
            account_tokens: None,
            min_validity_access_token: chrono::Duration::new(5, 0)
                .expect("Unable to construct default min validity")
                .into(),
            min_validity_access_token_target: chrono::Duration::new(30, 0)
                .expect("Unable to construct default min validity target")
                .into(),
            min_validity_id_token: chrono::Duration::new(5, 0)
                .expect("Unable to construct default min validity")
                .into(),
            updater: None,
            verifier: verifier.into(),
            access_token_type: std::marker::PhantomData,
            account_user_type: std::marker::PhantomData,
            state_token_avail: std::marker::PhantomData,
            state_confidential_client: std::marker::PhantomData,
        }
    }
}

impl<AC, IC, APM, ATT, AUT>
    Account<AC, IC, APM, ATT, AUT, crate::types::AttributeSet, crate::types::AttributeNotSet>
where
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType,
    AUT: account_user_type::AccountUserType,
{
    /// Creates a new Account object for a specific confidential client.
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc6749#section-2.1> for more details.
    pub fn from_secret_client(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: String,
        client_secret: String,
        verifier: crate::verifier::Verifier<AC, IC, APM>,
    ) -> Self {
        Self {
            idp: idp.into(),
            client_id: openidconnect::ClientId::new(client_id),
            client_secret: Some(openidconnect::ClientSecret::new(client_secret)),
            account_tokens: None,
            min_validity_access_token: chrono::Duration::new(5, 0)
                .expect("Unable to construct default min validity")
                .into(),
            min_validity_access_token_target: chrono::Duration::new(30, 0)
                .expect("Unable to construct default min validity target")
                .into(),
            min_validity_id_token: chrono::Duration::new(5, 0)
                .expect("Unable to construct default min validity")
                .into(),
            updater: None,
            verifier: verifier.into(),
            access_token_type: std::marker::PhantomData,
            account_user_type: std::marker::PhantomData,
            state_token_avail: std::marker::PhantomData,
            state_confidential_client: std::marker::PhantomData,
        }
    }
}

impl<AC, IC, APM, ATT>
    Account<
        AC,
        IC,
        APM,
        ATT,
        account_user_type::ServiceAccount,
        crate::types::AttributeSet,
        crate::types::AttributeNotSet,
    >
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
{
    /// Exchanges the client credentials of a secret client via the Client Credentials Grant.
    ///
    /// This is intended for using the service account of an IdP
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc6749#section-4.4> for more details about the Client Credentials Grant.
    pub async fn exchange_client_credentials(
        self,
        scopes: Vec<String>,
    ) -> Result<
        Account<
            AC,
            IC,
            APM,
            ATT,
            account_user_type::ServiceAccount,
            crate::types::AttributeSet,
            crate::types::AttributeSet,
        >,
        AccountError,
    > {
        let client = self.get_client().await?;
        let client_creds_token_request = client
            .exchange_client_credentials()?
            .add_scopes(scopes.into_iter().map(openidconnect::Scope::new));
        let token_response = client_creds_token_request
            .request_async(&*self.idp.reqwest_client)
            .await?;

        self.process_token_response(token_response, None).await
    }
}

impl<AC, IC, APM, ATT, AUT, IsConfidentialClient, AreAccountTokenAvailable>
    Account<AC, IC, APM, ATT, AUT, IsConfidentialClient, AreAccountTokenAvailable>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AreAccountTokenAvailable: crate::types::AttributeState,
    IsConfidentialClient: crate::types::AttributeState,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
    AUT: account_user_type::AccountUserType,
{
    /// Returns an internal client, derived from openidconnect crate
    async fn get_client(&self) -> Result<crate::types::OidcClient<IC>, AccountError> {
        Self::static_get_client(
            self.idp.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .await
    }

    async fn static_get_client(
        idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
        client_id: openidconnect::ClientId,
        client_secret: Option<openidconnect::ClientSecret>,
    ) -> Result<crate::types::OidcClient<IC>, AccountError> {
        Ok(crate::types::OidcClient::<IC>::from_provider_metadata(
            idp.discovery_attributes().await?,
            client_id,
            client_secret,
        ))
    }

    // Prepared for future use
    // /// Helper function to support e.g. IdP caching
    // pub(crate) fn get_idp(self) -> crate::idp::IdP<APM, crate::types::AttributeSet> {
    //     (*self.idp).clone()
    // }

    /// Processes a token response after e.g. new tokens are obtained
    ///
    /// Returns a new Account with the same data as self, except the account tokens are set form the response
    async fn process_token_response(
        self,
        token_response: openidconnect::StandardTokenResponse<
            openidconnect::IdTokenFields<
                IC,
                openidconnect::EmptyExtraTokenFields,
                openidconnect::core::CoreGenderClaim,
                openidconnect::core::CoreJweContentEncryptionAlgorithm,
                openidconnect::core::CoreJwsSigningAlgorithm,
            >,
            openidconnect::core::CoreTokenType,
        >,
        nonce: Option<openidconnect::Nonce>,
    ) -> Result<
        Account<AC, IC, APM, ATT, AUT, IsConfidentialClient, crate::types::AttributeSet>,
        AccountError,
    > {
        let fresh_account_tokens =
            Self::static_process_token_response(token_response, self.verifier.clone(), nonce)
                .await?;

        let locked_account_tokens = {
            if let Some(account_tokens_lock) = self.account_tokens {
                {
                    let mut writable = account_tokens_lock.write().await;
                    *writable = fresh_account_tokens;
                }
                account_tokens_lock
            } else {
                std::sync::Arc::new(tokio::sync::RwLock::new(fresh_account_tokens))
            }
        };

        Ok(Account {
            idp: self.idp,
            client_id: self.client_id,
            client_secret: self.client_secret,
            account_tokens: Some(locked_account_tokens),
            min_validity_access_token: self.min_validity_access_token,
            min_validity_access_token_target: self.min_validity_access_token_target,
            min_validity_id_token: self.min_validity_id_token,
            updater: self.updater,
            verifier: self.verifier,
            access_token_type: std::marker::PhantomData,
            account_user_type: std::marker::PhantomData,
            state_token_avail: std::marker::PhantomData,
            state_confidential_client: std::marker::PhantomData,
        })
    }

    /// Processes a token response after e.g. new tokens are obtained. Static version to be also called from updater.
    ///
    /// Security warning: Be careful when passing None as nonce. This nonce is required e.g. to prevent replay attacks in SPA applications. If you can, please set it. See also https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    async fn static_process_token_response(
        token_response: openidconnect::StandardTokenResponse<
            openidconnect::IdTokenFields<
                IC,
                openidconnect::EmptyExtraTokenFields,
                openidconnect::core::CoreGenderClaim,
                openidconnect::core::CoreJweContentEncryptionAlgorithm,
                openidconnect::core::CoreJwsSigningAlgorithm,
            >,
            openidconnect::core::CoreTokenType,
        >,
        verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,
        nonce: Option<openidconnect::Nonce>,
    ) -> Result<AccountTokens<IC>, AccountError> {
        let access_token = token_response.access_token().secret().to_string();

        let id_token = token_response.id_token();

        // check whether tokens match
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.6
        let mut expected_access_token_hash = None;
        let id_token_claims = {
            if let Some(unpacked_id_token) = &id_token {
                let id_token_claims = verifier
                    .verify_identity_token(&unpacked_id_token.to_string(), nonce)
                    .await?;
                if let Some(access_token_hash) = id_token_claims.access_token_hash() {
                    expected_access_token_hash = Some(access_token_hash.clone());
                }
                Some(id_token_claims)
            } else {
                None
            }
        };

        let access_token_expiry = ATT::handle(
            verifier,
            &access_token,
            expected_access_token_hash,
            token_response.expires_in(),
        )
        .await?;

        Ok(AccountTokens {
            refresh_token: token_response
                .refresh_token()
                .map(|val| val.secret().to_string()),
            access_token: token_response.access_token().secret().to_string(),
            access_token_expiry,
            id_token_claims,
        })
    }
}

impl<AC, IC, APM, ATT, AUT, IsConfidentialClient>
    Account<AC, IC, APM, ATT, AUT, IsConfidentialClient, crate::types::AttributeNotSet>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    IsConfidentialClient: crate::types::AttributeState,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
    AUT: account_user_type::AccountUserType,
{
    /// Exchange username/password combination for a set of account tokens.
    ///
    /// This uses the direct grant flow, which is deprecated in the OpenID standard.
    /// If possible, please use another flow, especially if you are running a web app etc.
    ///
    /// There are only a very few cases where this flow might make sense.
    ///
    /// Therefore, it is deprecated in the standard.
    ///
    /// Returns a new Account.
    pub async fn exchange_password(
        self,
        username: String,
        password: String,
        scopes: Vec<String>,
    ) -> Result<
        Account<AC, IC, APM, ATT, AUT, IsConfidentialClient, crate::types::AttributeSet>,
        AccountError,
    > {
        let client = self.get_client().await?;

        let resource_owner_username = openidconnect::ResourceOwnerUsername::new(username);
        let resource_owner_password = openidconnect::ResourceOwnerPassword::new(password);
        let tok = client
            .exchange_password(&resource_owner_username, &resource_owner_password)?
            .add_scopes(scopes.into_iter().map(openidconnect::Scope::new));
        let token_response = tok.request_async(&*self.idp.reqwest_client).await?;

        self.process_token_response(token_response, None).await
    }

    /// Exchange refresh token for a set of account tokens.
    ///
    /// Returns a new Account.
    pub async fn exchange_refresh_token(
        self,
        refresh_token: String,
    ) -> Result<
        Account<AC, IC, APM, ATT, AUT, IsConfidentialClient, crate::types::AttributeSet>,
        AccountError,
    > {
        let client = self.get_client().await?;

        let current_refresh_token = openidconnect::RefreshToken::new(refresh_token);
        let tok = client.exchange_refresh_token(&current_refresh_token)?;
        let token_response = tok.request_async(&*self.idp.reqwest_client).await?;

        self.process_token_response(token_response, None).await
    }

    /// Exchange code to token set. PKCE version. The caller is responsible to check the CSRF token if necessary.
    ///
    /// For checking the CSRF token, see also <https://datatracker.ietf.org/doc/html/rfc6749#section-10.12>
    ///
    /// Returns a new Account and the original redirect URL the user should get redirected to.
    ///
    /// Intended usage:
    ///
    /// 1. Caller calls [`authorize_url_pkce`](Account::authorize_url_pkce)
    /// 1. Library generates PKCE state with verifier (serializable)
    /// 1. Caller should store state (e.g. client-side as cookie or server-side)
    /// 1. Caller redirects user in browser
    /// 1. Caller receives URL at callback URL
    /// 1. Caller calls `exchange_code_pkce`
    /// 1. Caller receives tokens
    pub async fn exchange_code_pkce(
        self,
        code: String,
        authorize_state: AuthorizePkceState,
    ) -> Result<PkceCodeExchangeResult<AC, IC, APM, ATT, AUT, IsConfidentialClient>, AccountError>
    {
        let client =
            self.get_client()
                .await?
                .set_redirect_uri(openidconnect::RedirectUrl::from_url(
                    authorize_state.callback_url,
                ));
        let token_response = client
            .exchange_code(openidconnect::AuthorizationCode::new(code))?
            .set_pkce_verifier(authorize_state.pkce_verifier)
            .request_async(&*self.idp.reqwest_client)
            .await?;

        Ok(PkceCodeExchangeResult {
            account: self
                .process_token_response(token_response, Some(authorize_state.nonce))
                .await?,
            url: authorize_state.redirect_url,
        })
    }

    /// Use this to generate a URL to redirect the user agent for authentication,
    /// as well as the state needed to verify a response then they come back
    ///
    /// Callback URL is the URL the IdP will redirect back to.
    ///
    /// Redirect URL is the URL the user should get redirected to after PKCE authentication is successfully performed.
    ///
    /// See [`exchange_code_pkce`](Account::exchange_code_pkce) for general usage instructions.
    pub async fn authorize_url_pkce(
        &self,
        scopes: Vec<String>,
        callback_url: url::Url,
        redirect_url: Option<url::Url>,
    ) -> Result<(url::Url, AuthorizePkceState), AccountError> {
        let (pkce_challenge, pkce_verifier) = openidconnect::PkceCodeChallenge::new_random_sha256();

        let client = self
            .get_client()
            .await?
            .set_redirect_uri(openidconnect::RedirectUrl::from_url(callback_url.clone()));

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                openidconnect::core::CoreAuthenticationFlow::AuthorizationCode,
                openidconnect::CsrfToken::new_random,
                openidconnect::Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(scopes.into_iter().map(openidconnect::Scope::new))
            .url();

        Ok((
            auth_url,
            AuthorizePkceState {
                pkce_verifier,
                csrf_token,
                nonce,
                callback_url,
                redirect_url,
            },
        ))
    }
}

impl<AC, IC, APM, ATT, AUT, IsConfidentialClient>
    Account<AC, IC, APM, ATT, AUT, IsConfidentialClient, crate::types::AttributeSet>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
    AUT: account_user_type::AccountUserType + Send + Sync + 'static,
    IsConfidentialClient: crate::types::AttributeState,
{
    /// Returns a currently valid access token. If it is not valid anymore, it returns an TokenTooOld Error.
    ///
    /// Use this function to obtain an access token for usage with another API etc.
    ///
    /// Do not use this function if you are driving async tasks within the same thread (you are in an async function).
    /// Use [`get_access_token`](`Account::get_access_token`) instead.
    pub fn get_access_token_blocking(&self) -> Result<String, AccountError> {
        if self
            .account_tokens
            .as_ref()
            .unwrap()
            .blocking_read()
            .access_token_expiry
            < chrono::offset::Utc::now() + *self.min_validity_access_token
        {
            return Err(AccountError::TokenTooOld());
        }

        self.get_access_token_outdated_blocking()
    }

    /// Returns a currently valid access token. If it is not valid anymore, it returns an TokenTooOld Error.
    ///
    /// Use this function to obtain an access token for usage with another API etc.
    ///
    /// If you need a non-async access token, please use [`get_access_token_blocking`](`Account::get_access_token_blocking`) instead.
    pub async fn get_access_token(&self) -> Result<String, AccountError> {
        if self
            .account_tokens
            .as_ref()
            .unwrap()
            .read()
            .await
            .access_token_expiry
            < chrono::offset::Utc::now() + *self.min_validity_access_token
        {
            return Err(AccountError::TokenTooOld());
        }

        self.get_access_token_outdated().await
    }

    /// Gets the access token from last refresh, even if it is outdated.
    ///
    /// Whenever you can, please use [`get_access_token_blocking`](`Account::get_access_token_blocking`)
    ///
    /// Do not use this function if you are driving async tasks within the same thread (you are in an async function).
    pub fn get_access_token_outdated_blocking(&self) -> Result<String, AccountError> {
        Ok(self
            .account_tokens
            .as_ref()
            .unwrap()
            .blocking_read()
            .access_token
            .clone())
    }

    /// Gets the access token from last refresh, even if it is outdated.
    ///
    /// Whenever you can, please use [`get_access_token`](`Account::get_access_token`)
    pub async fn get_access_token_outdated(&self) -> Result<String, AccountError> {
        Ok(self
            .account_tokens
            .as_ref()
            .unwrap()
            .read()
            .await
            .access_token
            .clone())
    }

    /// Returns a currently valid id token. If it is not valid anymore, it returns an TokenTooOld Error.
    ///
    /// Use this function to obtain an id token for usage with another API etc.
    ///
    /// Do not use this function if you are driving async tasks within the same thread (you are in an async function).
    /// Use [`get_id_token`](`Account::get_id_token_claims`) instead.
    pub fn get_id_token_claims_blocking(
        &self,
    ) -> Result<
        Option<openidconnect::IdTokenClaims<IC, openidconnect::core::CoreGenderClaim>>,
        AccountError,
    > {
        if self
            .account_tokens
            .as_ref()
            .unwrap()
            .blocking_read()
            .access_token_expiry
            < chrono::offset::Utc::now() + *self.min_validity_access_token
        {
            return Err(AccountError::TokenTooOld());
        }

        self.get_id_token_claims_outdated_blocking()
    }

    /// Returns a currently valid id token. If it is not valid anymore, it returns an TokenTooOld Error.
    ///
    /// Use this function to obtain an id token for usage with another API etc.
    ///
    /// If you need a non-async id token, please use [`get_id_token_blocking`](`Account::get_id_token_claims_blocking`) instead.
    pub async fn get_id_token_claims(
        &self,
    ) -> Result<
        Option<openidconnect::IdTokenClaims<IC, openidconnect::core::CoreGenderClaim>>,
        AccountError,
    > {
        if let Some(id_token) = self
            .account_tokens
            .as_ref()
            .unwrap()
            .read()
            .await
            .id_token_claims
            .as_ref()
            && id_token.expiration() < chrono::offset::Utc::now() + *self.min_validity_id_token
        {
            return Err(AccountError::TokenTooOld());
        }

        self.get_id_token_claims_outdated().await
    }

    /// Gets the id token from last refresh, even if it is outdated.
    ///
    /// Whenever you can, please use [`get_id_token_blocking`](`Account::get_id_token_claims_blocking`)
    ///
    /// Do not use this function if you are driving async tasks within the same thread (you are in an async function).
    pub fn get_id_token_claims_outdated_blocking(
        &self,
    ) -> Result<
        Option<openidconnect::IdTokenClaims<IC, openidconnect::core::CoreGenderClaim>>,
        AccountError,
    > {
        Ok(self
            .account_tokens
            .as_ref()
            .unwrap()
            .blocking_read()
            .id_token_claims
            .clone())
    }

    /// Gets the id token from last refresh, even if it is outdated.
    ///
    /// Whenever you can, please use [`get_id_token`](`Account::get_id_token_claims`)
    pub async fn get_id_token_claims_outdated(
        &self,
    ) -> Result<
        Option<openidconnect::IdTokenClaims<IC, openidconnect::core::CoreGenderClaim>>,
        AccountError,
    > {
        Ok(self
            .account_tokens
            .as_ref()
            .unwrap()
            .read()
            .await
            .id_token_claims
            .clone())
    }

    /// Starts automatically refreshing tokens and refreshes tokens if possible.
    pub fn start_auto_refresh(mut self) -> Self {
        self.updater = Some(std::sync::Arc::new(
            AUT::get_updater::<AC, IC, APM, ATT, AUT>(
                self.idp.clone(),
                self.account_tokens.clone().unwrap(),
                self.client_id.clone(),
                self.client_secret.clone(),
                self.min_validity_access_token_target.clone(),
                self.verifier.clone(),
            ),
        ));

        self
    }
}

#[derive(Debug, Clone)]
struct UpdaterImpl<AC, IC, APM, ATT, AUT>
where
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq,
    ATT: access_token_type::AccessTokenType,
    AUT: account_user_type::AccountUserType,
{
    idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
    account_tokens: std::sync::Arc<tokio::sync::RwLock<AccountTokens<IC>>>,
    client_id: openidconnect::ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    min_validity_access_token_target: std::sync::Arc<chrono::TimeDelta>,
    verifier: std::sync::Arc<crate::verifier::Verifier<AC, IC, APM>>,

    access_token_type: std::marker::PhantomData<ATT>,
    account_user_type: std::marker::PhantomData<AUT>,
}

impl<AC, IC, APM, ATT, ATU> UpdaterImpl<AC, IC, APM, ATT, ATU>
where
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + std::marker::Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + std::marker::Sync + 'static,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + std::marker::Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
    ATU: account_user_type::AccountUserType,
{
    async fn get_next_refresh_datetime(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, AccountError> {
        let account_tokens = self.account_tokens.read().await;
        let expiry = account_tokens.access_token_expiry;
        let refresh_at = expiry - *self.min_validity_access_token_target;
        if refresh_at <= chrono::offset::Utc::now() {
            Ok(Some(
                chrono::offset::Utc::now()
                    + chrono::Duration::new(10, 0).expect("Unable to build chrono duration!"),
            ))
        } else {
            Ok(Some(refresh_at))
        }
    }
}

impl<AC, IC, APM, ATT> crate::updater::UpdaterImpl<AccountError>
    for UpdaterImpl<AC, IC, APM, ATT, account_user_type::User>
where
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + std::marker::Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + std::marker::Sync + 'static,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + std::marker::Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
{
    async fn get_next_update_time(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, AccountError> {
        let account_tokens = self.account_tokens.read().await;

        // if we have no refresh token, just exit and exit updater
        if account_tokens.refresh_token.is_none() {
            tracing::trace!("No refresh token present, exiting updater...");
            return Ok(None);
        }

        self.get_next_refresh_datetime().await
    }

    async fn do_update(&self) -> Result<(), AccountError> {
        let mut account_tokens = self.account_tokens.write().await;

        let client = Account::<AC, IC, APM, ATT, account_user_type::User, crate::types::AttributeSet>::static_get_client(
            self.idp.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .await?;
        let current_refresh_token = openidconnect::RefreshToken::new(
            account_tokens
                .refresh_token
                .clone()
                .ok_or(AccountError::NoRefreshtoken())?,
        );
        let new_token_request = client.exchange_refresh_token(&current_refresh_token)?;
        let token_response = new_token_request
            .request_async(&*self.idp.reqwest_client)
            .await?;

        tracing::trace!("Updated account tokens!");

        *account_tokens = Account::<
            AC,
            IC,
            APM,
            ATT,
            account_user_type::User,
            crate::types::AttributeSet,
        >::static_process_token_response(
            token_response, self.verifier.clone(), None
        )
        .await?;

        Ok(())
    }
}

impl<AC, IC, APM, ATT> crate::updater::UpdaterImpl<AccountError>
    for UpdaterImpl<AC, IC, APM, ATT, account_user_type::ServiceAccount>
where
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + std::marker::Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + std::marker::Sync + 'static,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + std::marker::Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
{
    async fn get_next_update_time(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, AccountError> {
        self.get_next_refresh_datetime().await
    }

    async fn do_update(&self) -> Result<(), AccountError> {
        let mut account_tokens = self.account_tokens.write().await;

        let client = Account::<
            AC,
            IC,
            APM,
            ATT,
            account_user_type::ServiceAccount,
            crate::types::AttributeSet,
        >::static_get_client(
            self.idp.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .await?;

        let new_token_response = match account_tokens.refresh_token.clone() {
            Some(refresh_token) => {
                let current_refresh_token = openidconnect::RefreshToken::new(refresh_token);
                let new_token_request = client.exchange_refresh_token(&current_refresh_token)?;
                new_token_request
                    .request_async(&*self.idp.reqwest_client)
                    .await?
            }
            None => {
                // Fallback to re-exchanging the client credentials
                let new_token_request = client.exchange_client_credentials()?;
                new_token_request
                    .request_async(&*self.idp.reqwest_client)
                    .await?
            }
        };
        tracing::trace!("Updated account tokens!");

        *account_tokens = Account::<
            AC,
            IC,
            APM,
            ATT,
            account_user_type::ServiceAccount,
            crate::types::AttributeSet,
        >::static_process_token_response(
            new_token_response, self.verifier.clone(), None
        )
        .await?;

        Ok(())
    }
}

/// Result struct for [`Account::exchange_code_pkce`].
pub struct PkceCodeExchangeResult<AC, IC, APM, ATT, AUT, IsConfidentialClient>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    IC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
    ATT: access_token_type::AccessTokenType + 'static,
    AUT: account_user_type::AccountUserType,
    IsConfidentialClient: crate::types::AttributeState,
{
    /// The [`Account`] object
    pub account: Account<AC, IC, APM, ATT, AUT, IsConfidentialClient, crate::types::AttributeSet>,
    /// URL the user should get redirected to after token verification.
    pub url: Option<url::Url>,
}
