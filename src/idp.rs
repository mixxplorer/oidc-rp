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

    #[error("JWKs too old. Refresh might have failed.")]
    DataTooOld(),
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct IdPAttributes<APM = EmptyAdditionalIdPMetadata>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq,
{
    base_url: url::Url,
    #[serde(bound(deserialize = "APM: openidconnect::AdditionalProviderMetadata"))]
    discovery: IdPAttributesDiscovery<APM>,
    last_data_refresh: chrono::DateTime<chrono::Utc>,
    data_usable_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct IdPAttributesShare<APM = EmptyAdditionalIdPMetadata>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq,
{
    #[serde(bound(deserialize = "APM: openidconnect::AdditionalProviderMetadata"))]
    attributes: IdPAttributes<APM>,
    // we have an extra field for JWKS as these are not serialized or deserialized with the IdPAttributesDiscovery struct
    jwk_set: openidconnect::JsonWebKeySet<openidconnect::core::CoreJsonWebKey>,
}

/// Identity Provider Object to provide information about the Identity Provider.
///
/// Supports any Identity Provider, which provide a openid-discover endpoint, like Keycloak.
///
/// To create a new Provider, please use [`IdP::new`]
#[derive(Clone, Debug)]
pub struct IdP<
    APM = EmptyAdditionalIdPMetadata,
    IsRefreshStrategySet = crate::types::AttributeNotSet,
> where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq,
    IsRefreshStrategySet: crate::types::AttributeState,
{
    attributes: std::sync::Arc<tokio::sync::RwLock<IdPAttributes<APM>>>,
    pub(crate) reqwest_client: std::sync::Arc<reqwest::Client>,
    idp_updater: Option<std::sync::Arc<crate::updater::Updater<IdPError>>>,

    // see https://doc.rust-lang.org/std/marker/struct.PhantomData.html
    phantom: std::marker::PhantomData<IsRefreshStrategySet>,
}

impl<APM, IsRefreshStrategySet> IdP<APM, IsRefreshStrategySet>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Sync + Send + 'static,
    IsRefreshStrategySet: crate::types::AttributeState,
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
    /// )?.set_default_jwks_refresh_strategy()?;
    ///
    /// // now you can access the jwks (across threads) for verifying access tokens
    /// idp.jwks()
    /// ```
    ///
    pub async fn new(base_url: url::Url) -> Result<Self, IdPError> {
        let reqwest_client_arc = std::sync::Arc::new(Self::build_reqwest_client()?);
        let discovery_attributes =
            Self::fetch_discovery_attributes(&reqwest_client_arc, base_url.clone()).await?;

        Ok(Self {
            attributes: tokio::sync::RwLock::new(IdPAttributes::<APM> {
                base_url,
                discovery: discovery_attributes,
                last_data_refresh: chrono::offset::Utc::now(),
                data_usable_until: None,
            })
            .into(),
            reqwest_client: reqwest_client_arc,
            idp_updater: None,
            phantom: std::marker::PhantomData,
        })
    }

    fn build_reqwest_client() -> Result<reqwest::Client, IdPError> {
        let reqwest_client = reqwest::Client::builder();
        // do not set redirect policy as this is handled by browser
        let reqwest_client = reqwest_client
            .redirect(reqwest::redirect::Policy::none())
            // do not set user agent as this might not be allowed due to CORS
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
            ))
            .referer(false);
        reqwest_client.build().map_err(|_| IdPError::FetchError)
    }

    async fn fetch_discovery_attributes(
        reqwest_client: &reqwest::Client,
        base_url: url::Url,
    ) -> Result<IdPAttributesDiscovery<APM>, IdPError> {
        Ok(IdPAttributesDiscovery::<APM>::discover_async(
            openidconnect::IssuerUrl::from_url(base_url),
            reqwest_client,
        )
        .await?)
    }

    /// Returns state of IdP to share in between processes. Intended to save on metadata requests.
    pub async fn state(&self) -> Result<IdPAttributesShare<APM>, IdPError> {
        let orig_attrs = self.attributes.read().await;
        Ok(IdPAttributesShare {
            attributes: orig_attrs.clone(),
            jwk_set: orig_attrs.discovery.jwks().clone(),
        })
    }

    /// Returns all attributes of the object.
    pub async fn attributes(&self) -> Result<IdPAttributes<APM>, IdPError> {
        let attrs = self.attributes.read().await;
        Ok(attrs.clone())
    }

    /// Returns base url passed during construction of object
    pub async fn base_url(&self) -> Result<url::Url, IdPError> {
        let attrs = self.attributes.read().await;
        Ok(attrs.base_url.clone())
    }

    /// Returns true if there is some JWKS refresh strategy running
    pub fn has_jwks_refresh_strategy(&self) -> bool {
        self.idp_updater.is_some()
    }
}

impl<APM> TryFrom<IdPAttributesShare<APM>> for IdP<APM, crate::types::AttributeNotSet>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Sync + Send + 'static,
{
    type Error = IdPError;

    /// Supports converting attributes to a full fledged IdP object.
    fn try_from(
        value: IdPAttributesShare<APM>,
    ) -> Result<IdP<APM, crate::types::AttributeNotSet>, Self::Error> {
        let reqwest_client_arc = std::sync::Arc::new(Self::build_reqwest_client()?);

        // restore correct JWKS
        let mut attrs = value.attributes;
        attrs.discovery = attrs.discovery.set_jwks(value.jwk_set);

        Ok(Self {
            attributes: tokio::sync::RwLock::new(attrs).into(),
            reqwest_client: reqwest_client_arc,
            idp_updater: None,
            phantom: std::marker::PhantomData,
        })
    }
}

/// Functions only available if a refresh strategy is in place
impl<APM> IdP<APM, crate::types::AttributeSet>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Sync + Send + 'static,
{
    /// Returns up-to-date discovery attributes according to IdP data refresh strategy.
    ///
    /// Returns up-to-date IdP data according to the refresh policy in use.
    /// Errors if data is too old.
    pub async fn discovery_attributes(&self) -> Result<IdPAttributesDiscovery<APM>, IdPError> {
        let attributes = self.attributes.read().await;

        // Check whether the IDP data got updated recently enough
        if let Some(jwks_usable_until) = attributes.data_usable_until {
            if jwks_usable_until < chrono::offset::Utc::now() {
                return Err(IdPError::DataTooOld());
            }
        }

        Ok(attributes.discovery.clone())
    }

    /// Returns the JWKS of the IdP.
    ///
    /// Returns up-to-date JWKS according to the refresh policy in use. Errors if data is too old.
    pub async fn jwks(&self) -> Result<openidconnect::JsonWebKeySet<IdPJsonWebKey>, IdPError> {
        Ok(self.discovery_attributes().await?.jwks().clone())
    }
}

/// Functions only available if a refresh strategy is not in place
impl<APM> IdP<APM, crate::types::AttributeNotSet>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Sync + Send + 'static,
{
    /// Returns possibly outdated discovery attributes.
    ///
    /// Returns discovery attributes which were fetched during object creation.
    pub async fn discovery_attributes_outdated(
        &self,
    ) -> Result<IdPAttributesDiscovery<APM>, IdPError> {
        let attributes = self.attributes.read().await;

        Ok(attributes.discovery.clone())
    }

    /// Returns posisbly outdated JWKS of the IdP.
    ///
    /// Returns JWKS which were fetched during object creation.
    pub async fn jwks_outdated(
        &self,
    ) -> Result<openidconnect::JsonWebKeySet<IdPJsonWebKey>, IdPError> {
        Ok(self.discovery_attributes_outdated().await?.jwks().clone())
    }

    /// Sets the JWKS refresh strategy and enables refreshing JWKS
    pub async fn set_idp_refresh_strategy<IRS>(
        self,
    ) -> Result<IdP<APM, crate::types::AttributeSet>, IdPError>
    where
        IRS: IdPRefreshStrategy + 'static,
    {
        let refresh_impl = RefreshImpl {
            reqwest_client: self.reqwest_client.clone(),
            attributes: self.attributes.clone(),
            base_url: self.base_url().await?,
            phantom_irs: std::marker::PhantomData::<IRS>,
        };
        Ok(IdP {
            attributes: self.attributes,
            reqwest_client: self.reqwest_client,
            idp_updater: Some(crate::updater::Updater::new(refresh_impl).into()),
            phantom: std::marker::PhantomData,
        })
    }

    /// Sets the IdP data refresh strategy to the default one and start refreshing IdP data
    pub async fn set_default_idp_refresh_strategy(
        self,
    ) -> Result<IdP<APM, crate::types::AttributeSet>, IdPError> {
        self.set_idp_refresh_strategy::<DefaultIdPDataRefreshStrategy>()
            .await
    }

    /// Set IdP data refresh strategy to a noop. This might be insecure!
    ///
    /// This is insecure if you use the IdP for more than ~2-3 minutes in time.
    /// If you use it longer, please use the default refresh strategy (or something similar).
    pub async fn set_no_idp_refresh_strategy(
        self,
    ) -> Result<IdP<APM, crate::types::AttributeSet>, IdPError> {
        self.set_idp_refresh_strategy::<NoIdPDataRefreshStrategy>()
            .await
    }
}

pub trait IdPRefreshStrategy: std::fmt::Debug + Clone + Send + Sync {
    /// When IdP data should get refreshed next time. Will not refresh at all if None.
    ///
    /// You must make sure to throttle requests, e.g. by providing a timestamp, which is always a few seconds in future.
    ///
    /// last_refresh is the time the current IdP data got fetched.
    fn next_refresh(
        last_refresh: &chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, IdPError>;

    /// Sets a upper time limit until the current IDP data are considered valid.
    ///
    /// If None is returned, no upper limit is given.
    ///
    /// last_refresh is the time the current IdP data got fetched.
    fn usable_until(
        last_refresh: &chrono::DateTime<chrono::Utc>,
    ) -> Result<chrono::DateTime<chrono::Utc>, IdPError>;
}

#[derive(Debug, Clone)]
struct RefreshImpl<APM, IRS>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq,
    IRS: IdPRefreshStrategy,
{
    reqwest_client: std::sync::Arc<reqwest::Client>,
    attributes: std::sync::Arc<tokio::sync::RwLock<IdPAttributes<APM>>>,
    base_url: url::Url,
    phantom_irs: std::marker::PhantomData<IRS>,
}

impl<APM, IRS> crate::updater::UpdaterImpl<IdPError> for RefreshImpl<APM, IRS>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + std::marker::Sync + 'static,
    IRS: IdPRefreshStrategy,
{
    async fn get_next_update_time(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, IdPError> {
        IRS::next_refresh(&{ self.attributes.clone().read().await.last_data_refresh })
    }

    async fn do_update(&self) -> Result<(), IdPError> {
        let timestamp_attribute_refresh = chrono::offset::Utc::now();
        let new_attrs = IdP::<APM, crate::types::AttributeSet>::fetch_discovery_attributes(
            &self.reqwest_client,
            self.base_url.clone(),
        )
        .await?;
        let data_usable_until = IRS::usable_until(&timestamp_attribute_refresh)?;
        {
            let mut writable_attributes = self.attributes.write().await;
            writable_attributes.discovery = new_attrs;
            writable_attributes.data_usable_until = Some(data_usable_until);
            writable_attributes.last_data_refresh = timestamp_attribute_refresh;
            log::trace!("Updated IdP Metadata!");
        }
        Ok::<(), IdPError>(())
    }
}

/// A refresh strategy, which refreshes the IdP data every five minutes (regardless of any HTTP caching).
/// If a refresh is not possible, it marks keys unusable after ten minutes.
///
/// The times are chosen in respect to proposed lifetimes of access tokens (about 2 minutes). Therefore, if an IdP
/// goes down, the current valid access tokens will work until they expire and after expiration we also invalidate
/// our cached IdP data like JWKS.
#[derive(Debug, Clone)]
pub struct DefaultIdPDataRefreshStrategy {}
impl DefaultIdPDataRefreshStrategy {
    const REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);
    const MIN_REFRESH_DISTANCE: std::time::Duration = std::time::Duration::from_secs(5);
    const INVALIDATE_AFTER: std::time::Duration = std::time::Duration::from_secs(10 * 60);
}

impl IdPRefreshStrategy for DefaultIdPDataRefreshStrategy {
    fn next_refresh(
        last_refresh: &chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, IdPError> {
        let next_planned_refresh = *last_refresh + Self::REFRESH_EVERY;
        let next_min_refresh = chrono::offset::Utc::now() + Self::MIN_REFRESH_DISTANCE;

        if next_planned_refresh > next_min_refresh {
            log::trace!("Providing planned refresh timestamp");
            return Ok(Some(next_planned_refresh));
        }
        log::trace!("Providing min refresh timestamp (possible after a failed request)");
        Ok(Some(next_min_refresh))
    }

    fn usable_until(
        last_refresh: &chrono::DateTime<chrono::Utc>,
    ) -> Result<chrono::DateTime<chrono::Utc>, IdPError> {
        Ok(*last_refresh + Self::INVALIDATE_AFTER)
    }
}

/// A refresh strategy, which just never refreshes anything.
///
/// This is intended to be used with one time IdP usages and will prevent using IdP metadata
/// after 10 minutes.
///
/// Please use the [`DefaultJwksRefreshStrategy`] for all other cases (or a similar strategy).
#[derive(Debug, Clone)]
pub struct NoIdPDataRefreshStrategy {}
impl NoIdPDataRefreshStrategy {
    const INVALIDATE_AFTER: std::time::Duration = std::time::Duration::from_secs(10 * 60);
}

impl IdPRefreshStrategy for NoIdPDataRefreshStrategy {
    fn next_refresh(
        _last_refresh: &chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, IdPError> {
        Ok(None)
    }

    fn usable_until(
        last_refresh: &chrono::DateTime<chrono::Utc>,
    ) -> Result<chrono::DateTime<chrono::Utc>, IdPError> {
        Ok(*last_refresh + Self::INVALIDATE_AFTER)
    }
}
