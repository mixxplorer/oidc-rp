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

    #[error("Unable to lock attribute RWLock. Lock seems to be poisoned.")]
    AttributeLockError(),
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
    account_tokens: Option<std::sync::Arc<std::sync::RwLock<AccountTokens>>>,
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
    fn get_client(&self) -> Result<crate::types::OidcClient, AccountError> {
        Self::static_get_client(
            self.idp.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
    }

    fn static_get_client(
        idp: std::sync::Arc<crate::idp::IdP<APM, crate::types::AttributeSet>>,
        client_id: openidconnect::ClientId,
        client_secret: Option<openidconnect::ClientSecret>,
    ) -> Result<crate::types::OidcClient, AccountError> {
        Ok(crate::types::OidcClient::from_provider_metadata(
            idp.discovery_attributes()?,
            client_id,
            client_secret,
        ))
    }

    /// Processes a token response after e.g. new tokens are obtained
    fn process_token_response(
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
        let fresh_account_tokens =
            Self::static_process_token_response(token_response, self.idp.clone(), self.client_id.clone())?;

        let locked_account_tokens = {
            if let Some(account_tokens_lock) = self.account_tokens {
                {
                    let mut writable = account_tokens_lock
                        .write()
                        .map_err(|_| AccountError::AttributeLockError())?;
                    *writable = fresh_account_tokens;
                }
                account_tokens_lock
            } else {
                std::sync::Arc::new(std::sync::RwLock::new(fresh_account_tokens))
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
    fn static_process_token_response(
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
        > = crate::verifier::Verifier::new_account_verifier(idp.as_ref().clone(), client_id.clone())?;
        let access_token_claims = access_token_verifier.verify_access_token(&access_token)?;
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
    pub fn exchange_password(
        self,
        username: &openidconnect::ResourceOwnerUsername,
        password: &openidconnect::ResourceOwnerPassword,
    ) -> Result<Account<APM, crate::types::AttributeSet>, AccountError> {
        let client = self.get_client()?;

        let tok = client.exchange_password(username, password)?;
        let token_response = tok.request(&*self.idp.reqwest_client)?;

        self.process_token_response(token_response)
    }

    /// Exchange refresh token for a set of account tokens.
    pub fn exchange_refresh_token(
        self,
        refresh_token: String,
    ) -> Result<Account<APM, crate::types::AttributeSet>, AccountError> {
        let client = self.get_client()?;

        let current_refresh_token = openidconnect::RefreshToken::new(refresh_token);
        let tok = client.exchange_refresh_token(&current_refresh_token)?;
        let token_response = tok.request(&*self.idp.reqwest_client)?;

        self.process_token_response(token_response)
    }
}

impl<APM> Account<APM, crate::types::AttributeSet>
where
    APM: openidconnect::AdditionalProviderMetadata + Send + Sync + 'static,
{
    /// Returns a currently valid access token. If it is not valid anymore, it returns an TokenTooOld Error.
    ///
    /// Use this function to obtain an access token for usage with another API etc.
    pub fn get_access_token(&self) -> Result<String, AccountError> {
        if self
            .account_tokens
            .as_ref()
            .unwrap()
            .read()
            .map_err(|_| AccountError::AttributeLockError())?
            .access_token_expiry
            < chrono::offset::Utc::now() + *self.min_validity_access_token
        {
            return Err(AccountError::TokenTooOld());
        }

        self.get_access_token_outdated()
    }

    /// Gets the access token from last refresh, even if it is outdated.
    ///
    /// Whenever you can, please use [`get_access_token`](`Account::get_access_token`)
    pub fn get_access_token_outdated(&self) -> Result<String, AccountError> {
        Ok(self
            .account_tokens
            .as_ref()
            .unwrap()
            .read()
            .map_err(|_| AccountError::AttributeLockError())?
            .access_token
            .clone())
    }

    /// Starts automatically refreshing tokens and refreshes tokens if possible.
    pub fn start_auto_refresh(mut self) -> Self {
        let updater_time_account_tokens = self.account_tokens.as_ref().unwrap().clone();
        let updater_time_min_validity_access_token_target =
            self.min_validity_access_token_target.clone();

        let updater_update_account_tokens = self.account_tokens.as_ref().unwrap().clone();
        let updater_update_idp = self.idp.clone();
        let updater_update_client_id = self.client_id.clone();
        let updater_update_client_secret = self.client_secret.clone();

        self.updater = Some(crate::updater::Updater::new(
            move || -> Result<Option<chrono::DateTime<chrono::Utc>>, AccountError> {
                let account_tokens = updater_time_account_tokens
                    .read()
                    .map_err(|_| AccountError::AttributeLockError())?;

                // if we have no refresh token, just exit and exit updater
                if account_tokens.refresh_token.is_none() {
                    log::trace!("No refresh token present, exiting updater...");
                    return Ok(None);
                }

                let expiry = account_tokens.access_token_expiry;
                let refresh_at = expiry - *updater_time_min_validity_access_token_target;
                if refresh_at <= chrono::offset::Utc::now() {
                    Ok(Some(chrono::offset::Utc::now() + chrono::Duration::new(10, 0).expect("Unable to build chrono duration!")))
                } else {
                    Ok(Some(refresh_at))
                }
            },
            move || -> Result<(), AccountError> {
                let mut account_tokens = updater_update_account_tokens
                    .write()
                    .map_err(|_| AccountError::AttributeLockError())?;

                let client = Self::static_get_client(
                    updater_update_idp.clone(),
                    updater_update_client_id.clone(),
                    updater_update_client_secret.clone(),
                )?;
                let current_refresh_token = openidconnect::RefreshToken::new(
                    account_tokens
                        .refresh_token
                        .clone()
                        .ok_or(AccountError::NoRefreshtoken())?,
                );
                let new_tokens = client.exchange_refresh_token(&current_refresh_token)?;
                let token_response = new_tokens.request(&*updater_update_idp.reqwest_client)?;

                log::trace!("Updated account tokens!");

                *account_tokens = Self::static_process_token_response(
                    token_response,
                    updater_update_idp.clone(),
                    updater_update_client_id.clone(),
                )?;

                Ok(())
            },
        ));

        self
    }
}
