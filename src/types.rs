mod private {
    /// Private trait, see https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
    pub trait AttributeSealedState {}
}

/// [Typestate](https://cliffle.com/blog/rust-typestate/) base trait indicating whether an attribute is set or not
pub trait AttributeState: private::AttributeSealedState {}

/// [Typestate](https://cliffle.com/blog/rust-typestate/) indicating an attribute is not set
#[derive(Clone, Debug)]
pub struct AttributeNotSet;
impl AttributeState for AttributeNotSet {}
impl private::AttributeSealedState for AttributeNotSet {}

/// [Typestate](https://cliffle.com/blog/rust-typestate/) indicating an attribute is set
#[derive(Clone, Debug)]
pub struct AttributeSet;
impl AttributeState for AttributeSet {}
impl private::AttributeSealedState for AttributeSet {}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GenericIdTokenFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

pub(crate) type OidcClient = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims,                   // AC
    openidconnect::core::CoreAuthDisplay,                   // AD
    openidconnect::core::CoreGenderClaim,                   // GC
    openidconnect::core::CoreJweContentEncryptionAlgorithm, // JE
    openidconnect::core::CoreJsonWebKey,                    // K
    openidconnect::core::CoreAuthPrompt,                    // P
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>, // TE
    openidconnect::core::CoreTokenResponse,                 // TR
    openidconnect::core::CoreTokenIntrospectionResponse,    // TIR
    openidconnect::core::CoreRevocableToken,                // RT
    openidconnect::core::CoreRevocationErrorResponse,       // TRE
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;
