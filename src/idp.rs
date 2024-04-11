/// Holds attributes we can parse from a openid-configuration file.
///
/// See https://openid.net/specs/openid-connect-discovery-1_0.html for a complete list of possible attributes.
/// Feel free to extend these attributes if you need additional ones.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OidcDiscoveryAttributes {
    issuer: url::Url,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    userinfo_endpoint: Option<url::Url>,
    jwks_uri: url::Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_endpoint: Option<url::Url>,
    response_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_supported: Option<Vec<String>>,
}

#[derive(thiserror::Error, Debug)]
pub enum IdPError {
    #[error("Unable to create IdP.")]
    UnableToCreateIdP(String),

    #[error("Unable to fetch data from IdP.")]
    FetchError,

    #[error("Fetching discovery endpoint returned an HTTP error code.")]
    DiscoveryStatusError(Option<u16>),

    #[error("Error parsing the JSON return of a endpoint.")]
    JsonParseError(#[from] reqwest::Error),

    #[error("Unable to lock attribute RWLock. Lock seems to be poisoned.")]
    AttributeLockError(#[from] std::sync::PoisonError<std::sync::RwLockReadGuard<'static, IdPAttributes>>),

    #[error("Unable to parse URL")]
    InvalidURL,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IdPAttributes {
    base_url: url::Url,
    discovery: OidcDiscoveryAttributes,
    jwk_set: jsonwebtoken::jwk::JwkSet,
}

#[derive(Clone, Debug)]
pub struct IdP {
    attributes: std::sync::Arc<std::sync::RwLock<IdPAttributes>>,
    reqwest_client: std::sync::Arc<reqwest::blocking::Client>,
    jwks_refresh_strategy: std::sync::Arc<Option<Box<dyn JwksRefreshStrategy>>>,

}

impl IdP {
    /// Creates a new identity provider object.
    ///
    /// # Examples
    ///
    /// ```
    /// let idp = IdP::new("https://keycloak.example.org/realms/test");
    /// // prime JWKS cache
    /// idp.jwks()
    ///
    /// ```
    pub fn new(base_url: url::Url) -> Result<Self, IdPError> {
        let reqwest_client = reqwest::blocking::Client::new();
        let discovery_url = base_url.join(crate::constants::OPENID_DISCOVERY_URI).map_err(|_| IdPError::InvalidURL)?;
        let discovery_attributes = reqwest_client
            .get(discovery_url)
            .send()
            .map_err(|_| IdPError::FetchError)?
            .error_for_status()
            .map_err(|error| {
                IdPError::DiscoveryStatusError(error.status().map(|err| err.as_u16()))
            })?
            .json::<OidcDiscoveryAttributes>()
            .map_err(|error| IdPError::JsonParseError(error))?;

        Ok(Self {
            attributes: std::sync::RwLock::new(IdPAttributes {
                base_url,
                discovery: discovery_attributes
            }).into(),
            reqwest_client: reqwest_client.into(),
            jwks_refresh_strategy: None.into(),
        })
    }

    /// Returns all attributes of the object. Intended to share state of IdP with other processes
    pub fn attributes(&self) -> Result<IdPAttributes, IdPError> {
        let attrs = self.attributes.read()?;
        Ok(attrs.clone())
    }

    /// Returns base url passed during construction of object
    pub fn base_url(&self) -> Result<url::Url, IdPError> {
        let attrs = self.attributes.read()?;
        Ok(attrs.base_url.clone())
    }

    /// Returns discovery attributes as fetched on object creation
    pub fn discovery_attributes(&self) -> Result<OidcDiscoveryAttributes, IdPError> {
        let attrs = self.attributes.read()?;
        Ok(attrs.discovery.clone())
    }

    /// Sets the JWKS refresh strategy and enables refreshing JWKS
    pub fn set_jwks_refresh_strategy(mut self, strategy: Box<dyn JwksRefreshStrategy>) {
        self.jwks_refresh_strategy = Some(strategy).into();

        let update_thread_idp = self.clone();
        std::thread::spawn(move || {
            loop {
                update_thread_idp.update_jwks();
            }
        });
    }

    // Sets the JWKS refresh strategy to the default one and start refreshing JWKS
    pub fn set_default_jwks_refresh_strategy(self) {
        self.set_jwks_refresh_strategy(Box::new(DefaultJwksRefreshStrategy {}));
    }

    /// Returns the JWKS of the IdP.
    ///
    /// Returns up-to-date JWKS according to the refresh policy in use.
    /// This function should typically return immediately, but it might block if the last JWKS update is considered too old and/or if there is no cached JWKS available.
    pub fn jwks(&self) {

    }

    fn update_jwks(&self) -> Result<(), IdPError> {
        let new_jwks = self.reqwest_client.get(self.discovery_attributes()?.jwks_uri).send().map_err(|_| IdPError::FetchError)?.error_for_status()?.json::<jsonwebtoken::jwk::JwkSet>()?;
        {
            self.attributes.write().jwkSet
        }
        Ok(())
    }
}


pub trait JwksRefreshStrategy: std::fmt::Debug + Send + Sync {
    /// Whether a refresh of the token is due. Should become true at least 60 seconds before is_usable becomes false.
    ///
    /// last_refresh is the time the current JWKS got fetched.
    /// TODO add cache header from request
    /// TODO add jwks itself
    fn refresh_needed(self, last_refresh: &std::time::SystemTime) -> bool;

    /// Whether a JWKS set is usable (can be used to verify).
    ///
    /// last_refresh is the time the current JWKS got fetched.
    /// TODO add cache header from request
    /// TODO add jwks itself
    fn is_usable(self, last_refresh: &std::time::SystemTime) -> bool;
}

#[derive(Debug)]
pub struct DefaultJwksRefreshStrategy {}
impl JwksRefreshStrategy for DefaultJwksRefreshStrategy {
    fn refresh_needed(self, last_refresh: &std::time::SystemTime) -> bool {
        match last_refresh.elapsed() {
            Ok(diff) => diff > std::time::Duration::from_secs(5 * 60),
            Err(_) => {
                log::error!("{:?} seems to be in future!", last_refresh);
                true // last_refresh seems to be off, just refresh
            },
        }
    }

    fn is_usable(self, last_refresh: &std::time::SystemTime) -> bool {
        match last_refresh.elapsed() {
            Ok(diff) => diff < std::time::Duration::from_secs(10 * 60),
            Err(_) => {
                log::error!("{:?} seems to be in future!", last_refresh);
                false // last_refresh seems to be off, just disallow usage
            },
        }
    }
}

#[derive(Debug)]
pub struct NoJwksRefreshStrategy {}
impl JwksRefreshStrategy for NoJwksRefreshStrategy {
    fn refresh_needed(self, _last_refresh: &std::time::SystemTime) -> bool {
        false
    }

    fn is_usable(self, _last_refresh: &std::time::SystemTime) -> bool {
        true
    }
}
