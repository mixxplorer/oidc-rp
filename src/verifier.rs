use std::str::FromStr;

#[derive(thiserror::Error, Debug)]
pub enum VerifierError {
    #[error("IdP returned an error. Probably the JWKS cannot be fetched?")]
    IdPError(#[from] crate::idp::IdPError),

    #[error("Unable to verify token!")]
    VerificationError(#[from] openidconnect::ClaimsVerificationError),

    #[error("Generic serde error!")]
    SerdeError(#[from] serde_json::Error),

    #[error("No IDP refresh strategy set!")]
    NoIdPDataRefreshStrategy(),
}

pub type JwtAccessTokenClaims<AC> =
    openidconnect::JwtAccessTokenClaims<AC, openidconnect::core::CoreGenderClaim>;

pub(crate) type JwtAccessToken<AC> = openidconnect::JwtAccessToken<
    AC,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
>;

pub struct Verifier<
    AC = openidconnect::EmptyAdditionalClaims,
    APM = crate::idp::EmptyAdditionalIdPMetadata,
> where
    APM: openidconnect::AdditionalProviderMetadata,
{
    idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
    client_id: openidconnect::ClientId,
    access_token_allowed_signing_algs: Option<Vec<openidconnect::core::CoreJwsSigningAlgorithm>>,
    access_token_allowed_jose_types: Option<Vec<openidconnect::JsonWebTokenType>>,
    other_audience_verifier_fn: fn(&openidconnect::Audience) -> bool,
    verify_own_audience: bool,

    // see https://doc.rust-lang.org/std/marker/struct.PhantomData.html
    phantom_additional_claims: std::marker::PhantomData<AC>,
}

impl<AC, APM> Verifier<AC, APM>
where
    AC: openidconnect::AdditionalClaims,
    APM: openidconnect::AdditionalProviderMetadata + Send + Sync + 'static,
{
    /// oidc_rp::oidc::EmptyAdditionalClaims
    pub fn new(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: openidconnect::ClientId,
    ) -> Result<Self, VerifierError> {
        // check whether idp is refreshing its metadata on a regular basis
        if !idp.has_jwks_refresh_strategy() {
            return Err(VerifierError::NoIdPDataRefreshStrategy());
        }

        // this is quite permissive, check again
        let access_token_allowed_signing_algs = Some(vec![
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP384Sha384,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP521Sha512,
            openidconnect::core::CoreJwsSigningAlgorithm::EdDsa,
        ]);
        let access_token_allowed_jose_types = Some(vec![
            openidconnect::JsonWebTokenType::new("at+jwt".to_string()),
            openidconnect::JsonWebTokenType::new("application/at+jwt".to_string()),
        ]);
        Ok(Self {
            idp,
            client_id,
            access_token_allowed_signing_algs,
            access_token_allowed_jose_types,
            other_audience_verifier_fn: |_| false,
            verify_own_audience: true,
            phantom_additional_claims: std::marker::PhantomData,
        })
    }

    /// Verifier to just extract the expiry time of access tokens
    pub(crate) fn new_account_verifier(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: openidconnect::ClientId,
    ) -> Result<Self, VerifierError> {
        Ok(Self {
            idp,
            client_id,
            access_token_allowed_signing_algs: None,
            access_token_allowed_jose_types: None,
            other_audience_verifier_fn: |_| true,
            verify_own_audience: false,
            phantom_additional_claims: std::marker::PhantomData,
        })
    }

    pub fn set_access_token_allowed_singing_algs(
        mut self,
        algs: Vec<openidconnect::core::CoreJwsSigningAlgorithm>,
    ) -> Self {
        self.access_token_allowed_signing_algs = Some(algs);
        self
    }

    pub fn set_access_token_allowed_jose_types(
        mut self,
        types: Vec<openidconnect::JsonWebTokenType>,
    ) -> Self {
        self.access_token_allowed_jose_types = Some(types);
        self
    }
    pub fn allow_all_access_token_jose_types(mut self) -> Self {
        self.access_token_allowed_jose_types = None;
        self
    }

    pub fn set_other_audience_verifier_fn(
        mut self,
        other_audience_verifier_fn: fn(&openidconnect::Audience) -> bool,
    ) -> Self {
        self.other_audience_verifier_fn = other_audience_verifier_fn;
        self
    }

    pub async fn verify_access_token(
        &self,
        jwt: &str,
    ) -> Result<JwtAccessTokenClaims<AC>, VerifierError> {
        let client = crate::types::OidcClient::from_provider_metadata(
            self.idp.discovery_attributes().await?,
            self.client_id.clone(),
            None,
        );

        // parse JWT from string
        let jwt: JwtAccessToken<AC> = openidconnect::JwtAccessToken::from_str(jwt)?;

        let mut verifier = client
            .jwt_access_token_verifier()
            .require_audience_match(true)
            .require_issuer_match(true)
            .require_audience_match(self.verify_own_audience)
            .enable_signature_check() // see RFC 9068 2.1
            .set_other_audience_verifier_fn(self.other_audience_verifier_fn); // allow other audiences in our token, which is the standard

        if let Some(allowed_algs) = self.access_token_allowed_signing_algs.clone() {
            verifier = verifier.set_allowed_algs(allowed_algs);
        }

        if let Some(types) = &self.access_token_allowed_jose_types {
            verifier = verifier.set_allowed_jose_types(types.clone());
        } else {
            verifier = verifier.allow_all_jose_types();
        }

        Ok(jwt.into_claims(&verifier)?)
    }
}
