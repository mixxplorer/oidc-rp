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

#[derive(Clone, Debug)]
pub struct AccountTokens {
    refresh_token: Option<String>,
    access_token: String,
    access_token_expiry: chrono::DateTime<chrono::Utc>,
    id_token: Option<String>,
}

/// Must be saved when losing all state
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuthorizePkceState {
    pub pkce_verifier: openidconnect::PkceCodeVerifier,
    pub csrf_token: openidconnect::CsrfToken,
    pub nonce: openidconnect::Nonce,
    pub callback_url: url::Url,
    pub redirect_url: url::Url,
}

#[derive(Debug, Clone)]
pub struct Account<
    APM = crate::idp::EmptyAdditionalIdPMetadata,
    AreAccountTokenAvailable = crate::types::AttributeNotSet,
    AC = openidconnect::EmptyAdditionalClaims,
> where
    APM: openidconnect::AdditionalProviderMetadata
        + PartialEq
        + Send
        + Sync
        + serde::de::DeserializeOwned,
    AreAccountTokenAvailable: crate::types::AttributeState + serde::de::DeserializeOwned,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
{
    idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
    client_id: openidconnect::ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    account_tokens: Option<std::sync::Arc<tokio::sync::RwLock<AccountTokens>>>,

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
    updater: Option<std::sync::Arc<crate::updater::Updater<AccountError>>>,
    verifier: std::sync::Arc<crate::verifier::Verifier<AC, APM>>,

    phantom: std::marker::PhantomData<AreAccountTokenAvailable>,
}

impl<APM, AC> Account<APM, crate::types::AttributeNotSet, AC>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
{
    /// Creates a new Account object for a specific public client.
    ///
    /// See https://www.rfc-editor.org/rfc/rfc6749#section-2.1 for more details.
    pub fn new_public(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: String,
        verifier: crate::verifier::Verifier<AC, APM>,
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
            updater: None,
            verifier: verifier.into(),
            phantom: std::marker::PhantomData,
        }
    }

    /// Creates a new Account object for a specific confidential client.
    ///
    /// See https://www.rfc-editor.org/rfc/rfc6749#section-2.1 for more details.
    pub fn new_secret(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: String,
        client_secret: String,
        verifier: crate::verifier::Verifier<AC, APM>,
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
            updater: None,
            verifier: verifier.into(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<APM, AreAccountTokenAvailable, AC> Account<APM, AreAccountTokenAvailable, AC>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AreAccountTokenAvailable: crate::types::AttributeState,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
{
    /// Returns an internal client, derived from openidconnect crate
    async fn get_client(&self) -> Result<crate::types::OidcClient, AccountError> {
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
    ) -> Result<crate::types::OidcClient, AccountError> {
        Ok(crate::types::OidcClient::from_provider_metadata(
            idp.discovery_attributes().await?,
            client_id,
            client_secret,
        ))
    }

    /// Helper function to support e.g. IdP caching in Leptos plugin
    #[cfg(feature = "leptos")]
    pub(crate) fn get_idp(self) -> crate::idp::IdP<APM, crate::types::AttributeSet> {
        (*self.idp).clone()
    }

    /// Processes a token response after e.g. new tokens are obtained
    ///
    /// Returns a new Account with the same data as self, except the account tokens are set form the response
    async fn process_token_response(
        self,
        token_response: openidconnect::StandardTokenResponse<
            openidconnect::IdTokenFields<
                openidconnect::EmptyAdditionalClaims,
                openidconnect::EmptyExtraTokenFields,
                openidconnect::core::CoreGenderClaim,
                openidconnect::core::CoreJweContentEncryptionAlgorithm,
                openidconnect::core::CoreJwsSigningAlgorithm,
            >,
            openidconnect::core::CoreTokenType,
        >,
        nonce: Option<openidconnect::Nonce>,
    ) -> Result<Account<APM, crate::types::AttributeSet, AC>, AccountError> {
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
            updater: self.updater,
            verifier: self.verifier,
            phantom: std::marker::PhantomData,
        })
    }

    /// Processes a token response after e.g. new tokens are obtained. Static version to be also called from updater.
    async fn static_process_token_response(
        token_response: openidconnect::StandardTokenResponse<
            openidconnect::IdTokenFields<
                openidconnect::EmptyAdditionalClaims,
                openidconnect::EmptyExtraTokenFields,
                openidconnect::core::CoreGenderClaim,
                openidconnect::core::CoreJweContentEncryptionAlgorithm,
                openidconnect::core::CoreJwsSigningAlgorithm,
            >,
            openidconnect::core::CoreTokenType,
        >,
        verifier: std::sync::Arc<crate::verifier::Verifier<AC, APM>>,
        nonce: Option<openidconnect::Nonce>,
    ) -> Result<AccountTokens, AccountError> {
        let id_token = token_response
            .id_token()
            .map(|id_token| id_token.to_string());

        let access_token = token_response.access_token().secret().to_string();

        // check whether tokens match
        // https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.6
        let mut expected_access_token_hash = None;
        if let Some(unpacked_id_token) = &id_token {
            let id_token_claims = verifier
                .verify_identity_token(unpacked_id_token, nonce)
                .await?;
            if let Some(access_token_hash) = id_token_claims.access_token_hash() {
                expected_access_token_hash = Some(access_token_hash.clone());
            }
        }

        // get access token expiry and verify hash match
        let access_token_claims = verifier
            .verify_access_token_with_hash(&access_token, expected_access_token_hash)
            .await?;
        let access_token_expiry = access_token_claims.expiration();

        Ok(AccountTokens {
            refresh_token: token_response
                .refresh_token()
                .map(|val| val.secret().to_string()),
            access_token: token_response.access_token().secret().to_string(),
            access_token_expiry,
            id_token,
        })
    }

    /// Exchange username/password combination for a set of account tokens.
    ///
    /// This uses the direct grant flow, which is deprecated in the OpenID standard.
    /// If possible, please use another flow, especially if you are running a web app etc.
    ///
    /// There are only a very few cases where this flow might make sense.
    ///
    /// Returns a new Account.
    pub async fn exchange_password(
        self,
        username: String,
        password: String,
    ) -> Result<Account<APM, crate::types::AttributeSet, AC>, AccountError> {
        let client = self.get_client().await?;

        let resource_owner_username = openidconnect::ResourceOwnerUsername::new(username);
        let resource_owner_password = openidconnect::ResourceOwnerPassword::new(password);
        let tok = client.exchange_password(&resource_owner_username, &resource_owner_password)?;
        let token_response = tok.request_async(&*self.idp.reqwest_client).await?;

        self.process_token_response(token_response, None).await
    }

    /// Exchange refresh token for a set of account tokens.
    ///
    /// Returns a new Account.
    pub async fn exchange_refresh_token(
        self,
        refresh_token: String,
    ) -> Result<Account<APM, crate::types::AttributeSet, AC>, AccountError> {
        let client = self.get_client().await?;

        let current_refresh_token = openidconnect::RefreshToken::new(refresh_token);
        let tok = client.exchange_refresh_token(&current_refresh_token)?;
        let token_response = tok.request_async(&*self.idp.reqwest_client).await?;

        self.process_token_response(token_response, None).await
    }

    /// Exchange code to token set. PKCE version. The caller is responsible to check the CSRF token if necessary.
    ///
    /// For checking the CSRF token, see also https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
    ///
    /// Returns a new Account.
    ///
    /// authorize_url_pkce -> save state, redirect to browser -> catch callback URL
    /// -> scrape code from own URL schema -> call exchange_code_pkce -> call start_refresh -> use tokens
    /// TODO: Make configurable.
    pub async fn exchange_code_pkce( // TODO: Never used in examples
        self,
        code: String,
        authorize_state: AuthorizePkceState,
    ) -> Result<Account<APM, crate::types::AttributeSet, AC>, AccountError> {
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

        self.process_token_response(token_response, Some(authorize_state.nonce))
            .await
    }

    /// Use this to generate a URL to redirect the user agent for authentication,
    /// as well as the state needed to verify a response then they come back
    pub async fn authorize_url_pkce(
        &self,
        scopes: Vec<String>,
        callback_url: url::Url,
        redirect_url: url::Url,
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
            .add_scopes(
                scopes
                    .into_iter()
                    .map(openidconnect::Scope::new),
            )
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

impl<APM, AC> Account<APM, crate::types::AttributeSet, AC>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
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

    /// Starts automatically refreshing tokens and refreshes tokens if possible.
    pub fn start_auto_refresh(mut self) -> Self {
        let updater_impl = UpdaterImpl {
            idp: self.idp.clone(),
            account_tokens: self.account_tokens.clone().unwrap(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            min_validity_access_token_target: self.min_validity_access_token_target.clone(),
            verifier: self.verifier.clone(),
        };

        self.updater = Some(crate::updater::Updater::new(updater_impl).into());

        self
    }
}

#[derive(Debug, Clone)]
struct UpdaterImpl<APM, AC>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + Sync + 'static,
{
    idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
    account_tokens: std::sync::Arc<tokio::sync::RwLock<AccountTokens>>,
    client_id: openidconnect::ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    min_validity_access_token_target: std::sync::Arc<chrono::TimeDelta>,
    verifier: std::sync::Arc<crate::verifier::Verifier<AC, APM>>,
}

impl<APM, AC> crate::updater::UpdaterImpl<AccountError> for UpdaterImpl<APM, AC>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + std::marker::Sync + 'static,
    AC: openidconnect::AdditionalClaims + Clone + PartialEq + Send + std::marker::Sync + 'static,
{
    async fn get_next_update_time(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, AccountError> {
        let account_tokens = self.account_tokens.read().await;

        // if we have no refresh token, just exit and exit updater
        if account_tokens.refresh_token.is_none() {
            log::trace!("No refresh token present, exiting updater...");
            return Ok(None);
        }

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

    async fn do_update(&self) -> Result<(), AccountError> {
        let mut account_tokens = self.account_tokens.write().await;

        let client = Account::<APM, crate::types::AttributeSet>::static_get_client(
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
        let new_tokens = client.exchange_refresh_token(&current_refresh_token)?;
        let token_response = new_tokens.request_async(&*self.idp.reqwest_client).await?;

        log::trace!("Updated account tokens!");

        *account_tokens =
            Account::<APM, crate::types::AttributeSet, AC>::static_process_token_response(
                token_response,
                self.verifier.clone(),
                None,
            )
            .await?;

        Ok(())
    }
}
