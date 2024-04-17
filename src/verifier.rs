#[derive(thiserror::Error, Debug)]
pub enum VerifierError {
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

    #[error("IdP returned an error. Probably the JWKS cannot be fetched?")]
    IdPError(#[from] crate::idp::IdPError),
}

type OidcIdTokenFields = openidconnect::IdTokenFields<
    openidconnect::EmptyAdditionalClaims,
    openidconnect::EmptyExtraTokenFields,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJwsSigningAlgorithm,
>;

type OidcTokenResponse =
    openidconnect::StandardTokenResponse<OidcIdTokenFields, openidconnect::core::CoreTokenType>;

type OidcClient = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims, // AC
    openidconnect::core::CoreAuthDisplay, // AD
    openidconnect::core::CoreGenderClaim, // GC
    openidconnect::core::CoreJweContentEncryptionAlgorithm, // JE
    openidconnect::core::CoreJsonWebKey, // K
    openidconnect::core::CoreAuthPrompt, // P
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>, // TE
    openidconnect::core::CoreTokenResponse, // TR
    openidconnect::core::CoreTokenIntrospectionResponse, // TIR
    openidconnect::core::CoreRevocableToken, // RT
    openidconnect::core::CoreRevocationErrorResponse, // TRE
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

/// Access token structure according RFC9068
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AccessTokenClaims
{
    #[serde(rename = "iss")]
    issuer: openidconnect::IssuerUrl,

    #[serde(rename = "exp", with = "openidconnect::helpers::serde_utc_seconds")]
    expiration: chrono::DateTime<chrono::Utc>,

    // We always serialize as an array, which is valid according to the spec. This sets the
    // 'default' attribute to be compatible with non-spec compliant OIDC providers that omit this
    // field.
    #[serde(
        default,
        rename = "aud",
        deserialize_with = "openidconnect::helpers::deserialize_string_or_vec"
    )]
    audiences: Vec<openidconnect::Audience>,

    sub: crate::types::Sub,

    client_id: openidconnect::ClientId,

    #[serde(rename = "iat", with = "openidconnect::helpers::serde_utc_seconds")]
    issue_time: chrono::DateTime<chrono::Utc>,

    #[serde(rename = "jti")]
    jwt_id: crate::types::JWTId,


    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "openidconnect::helpers::serde_utc_seconds_opt"
    )]
    auth_time: Option<chrono::DateTime<chrono::Utc>>,

    #[serde(rename = "acr", skip_serializing_if = "Option::is_none")]
    auth_context_ref: Option<openidconnect::AuthenticationContextClass>,

    #[serde(rename = "amr", skip_serializing_if = "Option::is_none")]
    auth_method_refs: Option<Vec<openidconnect::AuthenticationMethodReference>>,

    // todo: add scope (missing as there is only a serialize_space_delimited_vec, not deserialize)
}

pub struct Verifier {
    idp: crate::idp::IdP,
    client_id: openidconnect::ClientId,
}

impl Verifier {
    pub fn new(idp: crate::idp::IdP, client_id: openidconnect::ClientId) -> Self {
        Self { idp, client_id }
    }

    pub fn verify(self, jwt: &String) -> Result<(), VerifierError>
    {
        let client = OidcClient::from_provider_metadata(
            self.idp.discovery_attributes()?,
            self.client_id,
            None,
        );

        let tok = client.exchange_password(&openidconnect::ResourceOwnerUsername::new("user".to_string()), &openidconnect::ResourceOwnerPassword::new("user".to_string())).unwrap();
        let tok_res: openidconnect::StandardTokenResponse<openidconnect::IdTokenFields<openidconnect::EmptyAdditionalClaims, openidconnect::EmptyExtraTokenFields, openidconnect::core::CoreGenderClaim, openidconnect::core::CoreJweContentEncryptionAlgorithm, openidconnect::core::CoreJwsSigningAlgorithm>, openidconnect::core::CoreTokenType> = tok.request(&*self.idp.reqwest_client).unwrap();
        openidconnect::TokenResponse::id_token(&tok_res);

        // let jwt = openidconnect::JsonWebToken<openidconnect::core::CoreJweContentEncryptionAlgorithm, JS, P, S>

        let jwt: openidconnect::JsonWebToken<openidconnect::core::CoreJweContentEncryptionAlgorithm, openidconnect::core::CoreJwsSigningAlgorithm, AccessTokenClaims, openidconnect::JsonWebTokenJsonPayloadSerde> = serde_json::from_str(jwt).unwrap();
        // let verifier = openidconnect::JwtClaimsVerifier::new(
        //     self.client_id,
        //     self.idp.issuer()?,
        //     self.idp.jwks()?,
        // );

        let verifier = client.token_verifier();

        verifier.set_allowed_algs(vec![
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
            openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP256Sha256,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP384Sha384,
            openidconnect::core::CoreJwsSigningAlgorithm::EcdsaP521Sha512,
            openidconnect::core::CoreJwsSigningAlgorithm::EdDsa,
        ]);

        verifier.require_audience_match(true);
        verifier.require_issuer_match(true);
        verifier.require_signature_check(true); // see RFC 9068 2.1
        verifier.set_other_audience_verifier_fn(|_| true);

        verifier.verified_claims(jwt);

        Ok(())
    }
}
