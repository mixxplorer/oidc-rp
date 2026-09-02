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

    #[error("Unable to verify signature of token!")]
    TokenSignatureVerificationError(#[from] openidconnect::SignatureVerificationError),

    #[error("Unable to calculate signature of token!")]
    TokenSignatureCalculationError(#[from] openidconnect::SigningError),

    #[error("Expected token hash does not match with calculated token hash!")]
    TokenSignatureMismatchError(),
}

pub type JwtAccessTokenClaims<AC> =
    openidconnect::JwtAccessTokenClaims<AC, openidconnect::core::CoreGenderClaim>;

pub(crate) type JwtAccessToken<AC> = openidconnect::JwtAccessToken<
    AC,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
>;

pub type IdTokenClaims<AC> = openidconnect::IdTokenClaims<AC, openidconnect::core::CoreGenderClaim>;

pub(crate) type IdToken<AC> = openidconnect::IdToken<
    AC,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
>;

#[derive(Debug)]
pub struct Verifier<
    AC = openidconnect::EmptyAdditionalClaims,
    APM = crate::idp::EmptyAdditionalIdPMetadata,
> where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq,
{
    idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
    client_id: openidconnect::ClientId,
    access_token_allowed_signing_algs: Option<Vec<openidconnect::core::CoreJwsSigningAlgorithm>>,
    id_token_allowed_signing_algs: Option<Vec<openidconnect::core::CoreJwsSigningAlgorithm>>,
    access_token_allowed_jose_types: Option<Vec<openidconnect::NormalizedJsonWebTokenType>>,
    id_token_allowed_jose_types: Option<Vec<openidconnect::NormalizedJsonWebTokenType>>,
    other_audience_verifier_fn: fn(&openidconnect::Audience) -> bool,
    verify_own_audience: bool,

    // see https://doc.rust-lang.org/std/marker/struct.PhantomData.html
    phantom_additional_claims: std::marker::PhantomData<AC>,
}

impl<AC, APM> Verifier<AC, APM>
where
    AC: openidconnect::AdditionalClaims,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
{
    pub fn new(
        idp: crate::idp::IdP<APM, crate::types::AttributeSet>,
        client_id: String,
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
        let id_token_allowed_signing_algs = Some(vec![
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP384Sha384,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP521Sha512,
            openidconnect::core::CoreJwsSigningAlgorithm::EdDsa,
        ]);
        let access_token_allowed_jose_types = Some(vec![
            openidconnect::JsonWebTokenType::new("at+jwt".to_string())
                .normalize()
                .expect("at+jwt should be a valid JWT type"),
        ]);
        Ok(Self {
            idp,
            client_id: openidconnect::ClientId::new(client_id),
            access_token_allowed_signing_algs,
            id_token_allowed_signing_algs,
            access_token_allowed_jose_types,
            id_token_allowed_jose_types: None,
            other_audience_verifier_fn: |_| false,
            verify_own_audience: true,
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
        types: Vec<openidconnect::NormalizedJsonWebTokenType>,
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
        self.verify_access_token_with_hash(jwt, None).await
    }

    /// Helper function to verify an access token with hash as required during token fetching.
    /// As token fetching is done solely internally, we do not expose this function.
    pub(crate) async fn verify_access_token_with_hash(
        &self,
        jwt_str: &str,
        expected_access_token_hash: Option<openidconnect::AccessTokenHash>,
    ) -> Result<JwtAccessTokenClaims<AC>, VerifierError> {
        let client = crate::types::OidcClient::from_provider_metadata(
            self.idp.discovery_attributes().await?,
            self.client_id.clone(),
            None,
        );

        // parse JWT from string
        let jwt: JwtAccessToken<AC> = openidconnect::JwtAccessToken::from_str(jwt_str)?;

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

        if let Some(expected_access_token_hash) = expected_access_token_hash {
            let calculated_access_token_hash = openidconnect::AccessTokenHash::from_token(
                &openidconnect::AccessToken::new(jwt_str.to_string()),
                // this might be insecure if the token is not transferred via TLS directly between RP and IdP, but we catch unsigned tokens here
                jwt.signing_alg()?,
                jwt.signing_key(&verifier)?,
            )?;
            if calculated_access_token_hash != expected_access_token_hash {}
        }

        Ok(jwt.into_claims(&verifier)?)
    }

    /// Verify an identity token.
    ///
    /// Security warning: Be careful when passing None as nonce. This nonce is required e.g. to prevent replay attacks in SPA applications. If you can, please set it.
    /// See also https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    pub async fn verify_identity_token(
        &self,
        jwt: &str,
        nonce: Option<openidconnect::Nonce>,
    ) -> Result<IdTokenClaims<AC>, VerifierError> {
        let client = crate::types::OidcClient::from_provider_metadata(
            self.idp.discovery_attributes().await?,
            self.client_id.clone(),
            None,
        );

        // parse JWT from string
        let jwt: IdToken<AC> = openidconnect::IdToken::from_str(jwt)?;

        let mut verifier = client
            .id_token_verifier()
            .require_audience_match(true)
            .require_issuer_match(true)
            .require_audience_match(self.verify_own_audience)
            .enable_signature_check() // see RFC 9068 2.1
            .set_other_audience_verifier_fn(self.other_audience_verifier_fn);

        if let Some(allowed_algs) = self.id_token_allowed_signing_algs.clone() {
            verifier = verifier.set_allowed_algs(allowed_algs);
        }

        if let Some(types) = &self.id_token_allowed_jose_types {
            verifier = verifier.set_allowed_jose_types(types.clone());
        } else {
            verifier = verifier.allow_all_jose_types();
        }

        let nonce_verifier = |token_nonce_option: Option<&openidconnect::Nonce>| {
            match nonce {
                Some(unpacked_nonce) => {
                    openidconnect::NonceVerifier::verify(&unpacked_nonce, token_nonce_option)
                }
                None => {
                    match token_nonce_option {
                        Some(_) => {
                            Err("No nonce given to verify, but one was noted in the token!"
                                .to_string())
                        }
                        None => {
                            // Just do not verify the nonce as we do not have a nonce to verify.
                            // This is fine e.g. for direct grants and other flows where the handler is not handing control flow over to untrusted client.
                            Ok(())
                        }
                    }
                }
            }
        };

        Ok(jwt.into_claims(&verifier, nonce_verifier)?)
    }
}
