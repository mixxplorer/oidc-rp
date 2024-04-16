#[derive(thiserror::Error, Debug)]
pub enum IdPError {
    #[error("Unable to create IdP.")]
    UnableToCreateIdP(String),

    #[error("Unable to fetch data from IdP.")]
    FetchError,

    #[error("Fetching discovery endpoint failed")]
    DiscoveryError(
        #[from] openidconnect::DiscoveryError<openidconnect::HttpClientError<reqwest::Error>>,
    ),

    #[error("Error parsing the JSON return of a endpoint.")]
    JsonParseError(#[from] reqwest::Error),

    #[error("Next refresh is in past!")]
    NextRefreshFuture(#[from] std::time::SystemTimeError),

    #[error("Unable to lock attribute RWLock. Lock seems to be poisoned.")]
    AttributeLockError(),

    #[error("JWKs too old. Refresh might have failed.")]
    JWKSTooOld(),
}

pub type IdPJsonWebKey = openidconnect::core::CoreJsonWebKey;
pub type EmptyAdditionalIdPMetadata = openidconnect::EmptyAdditionalProviderMetadata;

type IdPAttributesDiscovery<APM> = openidconnect::ProviderMetadata<
    APM,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreClientAuthMethod,
    openidconnect::core::CoreClaimName,
    openidconnect::core::CoreClaimType,
    openidconnect::core::CoreGrantType,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJweKeyManagementAlgorithm,
    IdPJsonWebKey,
    openidconnect::core::CoreResponseMode,
    openidconnect::core::CoreResponseType,
    openidconnect::core::CoreSubjectIdentifierType,
>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IdPAttributes<APM>
where
    APM: openidconnect::AdditionalProviderMetadata,
{
    base_url: url::Url,
    #[serde(bound(deserialize = "APM: openidconnect::AdditionalProviderMetadata"))]
    discovery: IdPAttributesDiscovery<APM>,
    jwk_set: openidconnect::JsonWebKeySet<openidconnect::core::CoreJsonWebKey>,
    last_discovery_refresh: std::time::SystemTime,
    jwks_usable_until: Option<std::time::SystemTime>,
}

/// Identity Provider Object to provide information about the Identity Provider.
///
/// Supports any Identity Provider, which provide a openid-discover endpoint, like Keycloak.
///
/// To create a new Provider, please use [`IdP::new`]
#[derive(Clone, Debug)]
pub struct IdP<APM = EmptyAdditionalIdPMetadata>
where
    APM: openidconnect::AdditionalProviderMetadata,
{
    attributes: std::sync::Arc<std::sync::RwLock<IdPAttributes<APM>>>,
    reqwest_client: std::sync::Arc<reqwest::blocking::Client>,
    jwks_update_thread_stop: Option<std::sync::Arc<std::sync::RwLock<bool>>>,
}

impl<APM> IdP<APM>
where
    APM: openidconnect::AdditionalProviderMetadata + Sync + Send + 'static,
{
    /// Creates a new identity provider object.
    ///
    /// # Examples
    ///
    /// Just fetch IdP metadata:
    /// ```
    /// let idp = IdP::new("https://keycloak.example.org/realms/test");
    /// // get JWKs (beware: these are not automatically refreshed yet! Not recommended if you want to verify anything!)
    /// idp.jwks()
    ///
    /// ```
    ///
    /// Automatically refresh JWKs (to use for verifying access tokens)
    /// ```
    /// let mut idp = oidc_rp::idp::IdP::<oidc_rp::idp::EmptyAdditionalIdPMetadata>::new(
    ///     url::Url::parse("https://keycloak.example.org/realms/test")?,
    /// )?;
    /// idp.set_default_jwks_refresh_strategy()?;
    ///
    /// // now you can access the jwks (across threads) for verifying access tokens
    /// idp.jwks()
    /// ```
    ///
    pub fn new(base_url: url::Url) -> Result<Self, IdPError> {
        let reqwest_client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
            ))
            .build()
            .map_err(|_| IdPError::FetchError)?;
        let reqwest_client_arc = std::sync::Arc::new(reqwest_client);
        let discovery_attributes =
            Self::fetch_discovery_attributes(&*reqwest_client_arc, base_url.clone())?;

        Ok(Self {
            attributes: std::sync::RwLock::new(IdPAttributes::<APM> {
                base_url,
                discovery: discovery_attributes,
                jwk_set: openidconnect::JsonWebKeySet::new(vec![]),
                last_discovery_refresh: std::time::SystemTime::now(),
                jwks_usable_until: None,
            })
            .into(),
            reqwest_client: reqwest_client_arc,
            jwks_update_thread_stop: None,
        })
    }

    fn fetch_discovery_attributes(
        reqwest_client: &reqwest::blocking::Client,
        base_url: url::Url,
    ) -> Result<IdPAttributesDiscovery<APM>, IdPError> {
        Ok(IdPAttributesDiscovery::<APM>::discover(
            &openidconnect::IssuerUrl::from_url(base_url),
            reqwest_client,
        )?)
    }

    /// Returns all attributes of the object. Intended to share state of IdP with other processes
    pub fn attributes(&self) -> Result<IdPAttributes<APM>, IdPError> {
        let attrs = self
            .attributes
            .read()
            .map_err(|_| IdPError::AttributeLockError())?;
        Ok(attrs.clone())
    }

    /// Returns base url passed during construction of object
    pub fn base_url(&self) -> Result<url::Url, IdPError> {
        let attrs = self
            .attributes
            .read()
            .map_err(|_| IdPError::AttributeLockError())?;
        Ok(attrs.base_url.clone())
    }

    /// Returns discovery attributes as fetched on object creation
    pub fn discovery_attributes(&self) -> Result<IdPAttributesDiscovery<APM>, IdPError> {
        let attrs = self
            .attributes
            .read()
            .map_err(|_| IdPError::AttributeLockError())?;
        Ok(attrs.discovery.clone())
    }

    /// Sets the JWKS refresh strategy and enables refreshing JWKS
    pub fn set_jwks_refresh_strategy<JRS>(&mut self) -> Result<(), IdPError>
    where
        JRS: JwksRefreshStrategy,
    {
        // send stop signal to true for any prior refresh strategy to terminate
        if let Some(jwks_update_thread_stop) = &self.jwks_update_thread_stop {
            let mut stop = jwks_update_thread_stop.write().unwrap();
            *stop = true;
        }
        // create a new Arc and RwLock to not stop our new thread
        self.jwks_update_thread_stop = Some(std::sync::Arc::new(std::sync::RwLock::new(false)));

        let update_thread_reqwest = self.reqwest_client.clone();
        let update_thread_attributes = self.attributes.clone();
        let update_thread_base_url = self.base_url()?;
        let update_thread_stop = self.jwks_update_thread_stop.as_ref().unwrap().clone();
        std::thread::spawn(move || {
            loop {
                let update_result = (|| -> Result<bool, IdPError> {
                    let next_refresh_opt = JRS::next_refresh(&{
                        update_thread_attributes
                            .read()
                            .map_err(|_| IdPError::AttributeLockError())?
                            .last_discovery_refresh
                            .clone()
                    })?;
                    if let Some(next_refresh) = next_refresh_opt {
                        match next_refresh.duration_since(std::time::SystemTime::now()) {
                            Ok(duration) => {
                                std::thread::sleep(duration);
                            },
                            Err(error) => {
                                // duration is negative, just continue
                                log::warn!("Received negative duration from refresh strategy, you might want select a refresh strategy, which is returning timestamps with at least a few seconds in the future to prevent DoSing: {:?}", error);
                            },
                        }
                    } else {
                        log::info!("Exiting JWKS refresh thread as refresh policy does not request any refresh in future.");
                        // stop thread
                        return Ok(true);
                    }

                    if *update_thread_stop.read().unwrap() {
                        log::info!("Exiting JWKS refresh thread as base object says so.");
                        // stop thread
                        return Ok(true);
                    }

                    let timestamp_attribute_refresh = std::time::SystemTime::now();
                    let new_attrs = Self::fetch_discovery_attributes(
                        &*update_thread_reqwest,
                        update_thread_base_url.clone(),
                    )?;
                    let jwks_usable_until = JRS::usable_until(&timestamp_attribute_refresh)?;
                    {
                        let mut writable_attributes = update_thread_attributes
                            .write()
                            .map_err(|_| IdPError::AttributeLockError())?;
                        writable_attributes.discovery = new_attrs;
                        writable_attributes.jwks_usable_until = jwks_usable_until;
                        writable_attributes.last_discovery_refresh = timestamp_attribute_refresh;
                    }
                    Ok(false)
                })();
                match update_result {
                    Ok(res) => {
                        if res {
                            // handle stop thread request
                            break;
                        }
                        log::debug!("Updated JWKS!")
                    }
                    Err(error) => log::error!("Updating JWKS failed with {:?}", error),
                }
            }
        });
        Ok(())
    }

    // Sets the JWKS refresh strategy to the default one and start refreshing JWKS
    pub fn set_default_jwks_refresh_strategy(&mut self) -> Result<(), IdPError> {
        self.set_jwks_refresh_strategy::<DefaultJwksRefreshStrategy>()
    }

    /// Returns the JWKS of the IdP.
    ///
    /// Returns up-to-date JWKS according to the refresh policy in use.
    /// This function should typically return immediately, but it might block if the last JWKS update is considered too old and/or if there is no cached JWKS available.
    pub fn jwks(&self) -> Result<openidconnect::JsonWebKeySet<IdPJsonWebKey>, IdPError> {
        let attributes = self.attributes.read().map_err(|_| IdPError::AttributeLockError())?;

        // Check whether the JWKs got updated recently enough
        if let Some(jwks_usable_until) = attributes.jwks_usable_until {
            if jwks_usable_until < std::time::SystemTime::now() {
                return Err(IdPError::JWKSTooOld());
            }
        }

        Ok(attributes.discovery.jwks().clone())
    }
}

impl<APM> Drop for IdP<APM>
where
    APM: openidconnect::AdditionalProviderMetadata,
{
    /// Ensure the update thread is getting ended when dropping reference to main object.
    /// The main object is the only mean to access data produced by the update thread.
    fn drop(&mut self) {
        if let Some(jwks_update_thread_stop) = &self.jwks_update_thread_stop {
            let mut stop = jwks_update_thread_stop.write().unwrap();
            *stop = true;
        }
        log::trace!("Ending update thread...");
    }
}

pub trait JwksRefreshStrategy: std::fmt::Debug + Clone + Send + Sync {
    /// When JWKS should get refreshed next time. Will not refresh at all if None.
    ///
    /// You must make sure to throttle requests, e.g. by providing a timestamp, which is always a few seconds in future.
    ///
    /// last_refresh is the time the current JWKS got fetched.
    /// TODO add cache header from request
    /// TODO add jwks itself
    fn next_refresh(
        last_refresh: &std::time::SystemTime,
    ) -> Result<Option<std::time::SystemTime>, IdPError>;

    /// Sets a upper time limit until the current JWKS are considered valid.
    ///
    /// If None is returned, no upper limit is given.
    ///
    /// last_refresh is the time the current JWKS got fetched.
    /// TODO add cache header from request
    /// TODO add jwks itself
    fn usable_until(last_refresh: &std::time::SystemTime) -> Result<Option<std::time::SystemTime>, IdPError>;
}

/// A refresh strategy, which refreshes the JWKS every five minutes from the IdP (regardless of any HTTP caching).
/// If a refresh is not possible, it marks keys unusable after ten minutes.
///
/// The times are chosen in respect to proposed lifetimes of access tokens (about 2 minutes). Therefore, if an IdP
/// goes down, the current valid access tokens will work until they expire and after expiration we also invalidate
/// our cached JWKS.
#[derive(Debug, Clone)]
pub struct DefaultJwksRefreshStrategy {}
impl DefaultJwksRefreshStrategy {
    const REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);
    const MIN_REFRESH_DISTANCE: std::time::Duration = std::time::Duration::from_secs(5);
    const INVALIDATE_AFTER: std::time::Duration = std::time::Duration::from_secs(10 * 60);
}

impl JwksRefreshStrategy for DefaultJwksRefreshStrategy {
    fn next_refresh(
        last_refresh: &std::time::SystemTime,
    ) -> Result<Option<std::time::SystemTime>, IdPError> {

        let next_planned_refresh = *last_refresh + Self::REFRESH_EVERY;
        let next_min_refresh = std::time::SystemTime::now() + Self::MIN_REFRESH_DISTANCE;

        if next_planned_refresh > next_min_refresh {
            log::trace!("Providing planned refresh timestamp");
            return Ok(Some(next_planned_refresh))
        }
        log::trace!("Providing min refresh timestamp (possible after a failed request)");
        Ok(Some(next_min_refresh))
    }

    fn usable_until(last_refresh: &std::time::SystemTime) -> Result<Option<std::time::SystemTime>, IdPError> {
        Ok(Some(*last_refresh + Self::INVALIDATE_AFTER))
    }
}


/// A refresh strategy, which just never refreshes anything.
///
/// This is just a demo strategy, not intended to be used in real world scenarios.
/// Please use the [`DefaultJwksRefreshStrategy`].
#[derive(Debug, Clone)]
pub struct NoJwksRefreshStrategy {}
impl JwksRefreshStrategy for NoJwksRefreshStrategy {
    fn next_refresh(
        _last_refresh: &std::time::SystemTime,
    ) -> Result<Option<std::time::SystemTime>, IdPError> {
        Ok(None)
    }

    fn usable_until(_last_refresh: &std::time::SystemTime) -> Result<Option<std::time::SystemTime>, IdPError> {
        Ok(None)
    }
}
