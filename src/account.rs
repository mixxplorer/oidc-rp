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

pub struct Account<
    APM = crate::idp::EmptyAdditionalIdPMetadata,
    AreAccountTokenAvailable = crate::types::AttributeNotSet,
> where
    APM: openidconnect::AdditionalProviderMetadata + Send + Sync,
    AreAccountTokenAvailable: crate::types::AttributeState,
{
    idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
    client_id: openidconnect::ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    account_tokens: Option<std::sync::Arc<tokio::sync::RwLock<AccountTokens>>>,
    min_validity_access_token: std::sync::Arc<chrono::Duration>,
    min_validity_access_token_target: std::sync::Arc<chrono::Duration>,
    updater: Option<crate::updater::Updater<AccountError>>,

    phantom: std::marker::PhantomData<AreAccountTokenAvailable>,
}

impl<APM> Account<APM, crate::types::AttributeNotSet>
where
    APM: openidconnect::AdditionalProviderMetadata + Send + Sync + 'static,
{
    /// Creates a new Account object for a specific public client.
    pub fn new_public(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: String,
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
            phantom: std::marker::PhantomData,
        }
    }

    /// Creates a new Account object for a specific public client.
    pub fn new_secret(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: String,
        client_secret: String,
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
            phantom: std::marker::PhantomData,
        }
    }
}

impl<APM, AreAccountTokenAvailable> Account<APM, AreAccountTokenAvailable>
where
    APM: openidconnect::AdditionalProviderMetadata + Send + Sync + 'static,
    AreAccountTokenAvailable: crate::types::AttributeState,
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

    /// Processes a token response after e.g. new tokens are obtained
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
    ) -> Result<Account<APM, crate::types::AttributeSet>, AccountError> {
        let fresh_account_tokens = Self::static_process_token_response(
            token_response,
            self.idp.clone(),
            self.client_id.clone(),
        )
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
        idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
        client_id: openidconnect::ClientId,
    ) -> Result<AccountTokens, AccountError> {
        let id_token = token_response
            .id_token()
            .map(|id_token| id_token.to_string());

        let access_token = token_response.access_token().secret().to_string();
        let access_token_verifier: crate::verifier::Verifier<
            openidconnect::EmptyAdditionalClaims,
            APM,
        > = crate::verifier::Verifier::new_account_verifier(
            idp.as_ref().clone(),
            client_id.clone(),
        )?;
        let access_token_claims = access_token_verifier
            .verify_access_token(&access_token)
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
    /// If possible, please use another standard, especially if you are running a web app etc.
    ///
    /// There are only a very few cases where this flow might make sense.
    pub async fn exchange_password(
        self,
        username: &openidconnect::ResourceOwnerUsername,
        password: &openidconnect::ResourceOwnerPassword,
    ) -> Result<Account<APM, crate::types::AttributeSet>, AccountError> {
        let client = self.get_client().await?;

        let tok = client.exchange_password(username, password)?;
        let token_response = tok.request_async(&*self.idp.reqwest_client).await?;

        self.process_token_response(token_response).await
    }

    /// Exchange refresh token for a set of account tokens.
    pub async fn exchange_refresh_token(
        self,
        refresh_token: String,
    ) -> Result<Account<APM, crate::types::AttributeSet>, AccountError> {
        let client = self.get_client().await?;

        let current_refresh_token = openidconnect::RefreshToken::new(refresh_token);
        let tok = client.exchange_refresh_token(&current_refresh_token)?;
        let token_response = tok.request_async(&*self.idp.reqwest_client).await?;

        self.process_token_response(token_response).await
    }
}

impl<APM> Account<APM, crate::types::AttributeSet>
where
    APM: openidconnect::AdditionalProviderMetadata + Send + Sync + 'static,
{
    /// Returns a currently valid access token. If it is not valid anymore, it returns an TokenTooOld Error.
    ///
    /// Use this function to obtain an access token for usage with another API etc.
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
        };

        self.updater = Some(crate::updater::Updater::new(updater_impl));

        self
    }
}

#[derive(Debug, Clone)]
struct UpdaterImpl<APM>
where
    APM: openidconnect::AdditionalProviderMetadata,
{
    idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
    account_tokens: std::sync::Arc<tokio::sync::RwLock<AccountTokens>>,
    client_id: openidconnect::ClientId,
    client_secret: Option<openidconnect::ClientSecret>,
    min_validity_access_token_target: std::sync::Arc<chrono::TimeDelta>,
}

impl<APM> crate::updater::UpdaterImpl<AccountError> for UpdaterImpl<APM>
where
    APM: openidconnect::AdditionalProviderMetadata + Send + std::marker::Sync + 'static,
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
            Account::<APM, crate::types::AttributeSet>::static_process_token_response(
                token_response,
                self.idp.clone(),
                self.client_id.clone(),
            )
            .await?;

        Ok(())
    }
}
