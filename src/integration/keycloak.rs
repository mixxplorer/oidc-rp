/// A [`KeycloakTokenSupplier`](keycloak::KeycloakTokenSupplier) that caches tokens for their lifetime.
///
/// The [`keycloak`] crate provides a very simple [`KeycloakServiceAccountAdminTokenRetriever`](keycloak::KeycloakServiceAccountAdminTokenRetriever)
/// that re-authenticates with Keycloak on every request.
/// This can quickly add up to an undesirable and unnecessary number of requests.
///
/// This token supplier uses an [`Account`](crate::account::Account) with [automatic refresh](crate::account::Account::start_auto_refresh)
/// and thus only performs a token exchange when the old token is about to expire.
///
/// It only supplies tokens for one Keycloak instance.
/// It will panic if [`KeycloakTokenSupplier::get`](keycloak::KeycloakTokenSupplier::get)'s `url` parameter is not equal to the Keycloak base url used to create this object.
pub struct TokenSupplier {
    keycloak_base_url: crate::oidc::url::Url,
    keycloak_account: crate::account::Account<
        crate::oidc::EmptyAdditionalClaims,
        crate::oidc::EmptyAdditionalClaims,
        crate::oidc::EmptyAdditionalProviderMetadata,
        crate::account::access_token_type::Opaque,
        crate::account::account_user_type::ServiceAccount,
        crate::types::AttributeSet,
        crate::types::AttributeSet,
    >,
}

/// An error that indicates that a [`url`](crate::oidc::url::Url) is `cannot-be-a-base`.
#[derive(Debug, thiserror::Error)]
#[error("The url '{url}' is cannot-be-a-base.")]
pub struct UrlIsCannotBeABase {
    url: crate::oidc::url::Url,
}

/// Everything that can go wrong when creating a new [`TokenSupplier`].
#[derive(Debug, thiserror::Error)]
pub enum CreateTokenSupplierError {
    #[error("Unable to parse url.")]
    UrlParsing(#[from] crate::oidc::url::ParseError),
    #[error(transparent)]
    UrlIsCannotBeABase(#[from] UrlIsCannotBeABase),
    #[error("Error creating the IdP.")]
    IdP(#[from] crate::idp::IdPError),
    #[error("Error creating the Verifier.")]
    Verifier(#[from] crate::verifier::VerifierError),
    #[error("Error exchanging the client credentials.")]
    Account(#[from] crate::account::AccountError),
}

/// This function enforces that an URL is interpreted as if it had at least one trailing slash.
///
/// This is useful when concatenating URL segments using [`Url::join`](crate::oidc::url::Url::join),
/// especially when user-provided segments are at play where it is unclear whether they have a trailing slash.
///
/// In other words:
///
/// * If the `url` has at least one trailing slash, nothing happens.
/// * If the `url` has no trailing slash, one is added.
fn enforce_trailing_slash(
    mut url: crate::oidc::url::Url,
) -> Result<crate::oidc::url::Url, UrlIsCannotBeABase> {
    let success = match url.path_segments_mut() {
        Ok(mut segments) => {
            // Idea from https://users.rust-lang.org/t/what-would-be-the-proper-way-to-fix-extra-slashes-in-urls/98810/5
            segments.pop_if_empty().push("");
            true
        }
        // The `url` is cannot-be-a-base.
        Err(()) => false,
    };
    // This hoop is required due to the `Drop` impl of `PathSegmentsMut`:
    // Using `url` before the `Result` is dropped is impossible,
    // even in the `Err` case.
    if !success {
        return Err(UrlIsCannotBeABase { url });
    }
    Ok(url)
}

impl TokenSupplier {
    /// Creates a new token supplier object for the given `client_id`/`client_secret` on the given `realm` for the Keycloak instance at `keycloak_base_url`.
    pub async fn new(
        client_id: &str,
        client_secret: &str,
        realm: &str,
        keycloak_base_url: impl TryInto<crate::oidc::url::Url, Error = crate::oidc::url::ParseError>,
    ) -> Result<Self, CreateTokenSupplierError> {
        let get_idp = async |base_url| Ok(crate::idp::IdP::new(base_url).await?);
        Self::new_internal(client_id, client_secret, realm, get_idp, keycloak_base_url).await
    }

    /// Creates a new token supplier object like in [`new`](`TokenSupplier::new`) but with the ability to pass in an own reqwest object.
    ///
    /// Passing in an own reqwest client requires more considerations regarding security, therefore only use this function if you really need
    /// an own reqwest client (e.g. for trusting specific certificates).
    ///
    /// If possible, please use [`oidc_rp::reqwest_client::get_default_reqwest_client`](`crate::reqwest_client::get_default_reqwest_client`) to obtain a basic client builder.
    #[cfg(feature = "special-reqwest-client")]
    pub async fn new_with_reqwest_client(
        client_id: &str,
        client_secret: &str,
        realm: &str,
        keycloak_base_url: impl TryInto<crate::oidc::url::Url, Error = crate::oidc::url::ParseError>,
        http_client: reqwest::Client,
    ) -> Result<Self, CreateTokenSupplierError> {
        let get_idp = async |base_url| {
            Ok(crate::idp::IdP::new_with_reqwest_client(base_url, http_client).await?)
        };
        Self::new_internal(client_id, client_secret, realm, get_idp, keycloak_base_url).await
    }

    async fn new_internal(
        client_id: &str,
        client_secret: &str,
        realm: &str,
        get_idp: impl AsyncFnOnce(
            crate::oidc::url::Url,
        ) -> Result<crate::idp::IdP, CreateTokenSupplierError>,
        keycloak_base_url: impl TryInto<crate::oidc::url::Url, Error = crate::oidc::url::ParseError>,
    ) -> Result<Self, CreateTokenSupplierError> {
        let keycloak_base_url = enforce_trailing_slash(keycloak_base_url.try_into()?)?;
        let idp_base_url = keycloak_base_url.join("realms/")?.join(realm)?;
        let idp = get_idp(idp_base_url)
            .await?
            .set_default_idp_refresh_strategy()
            .await?;
        let verifier = crate::verifier::Verifier::<crate::oidc::EmptyAdditionalClaims>::new(
            idp.clone(),
            client_id.to_owned(),
        )?
        .set_access_token_allowed_jose_types(vec![
            crate::oidc::JsonWebTokenType::new("JWT".to_owned())
                .normalize()
                .expect("`JWT` should be a valid JSON Web Token Type."),
        ])
        .allow_other_audiences();
        let account = crate::account::Account::from_secret_client(
            idp,
            client_id.to_owned(),
            client_secret.to_owned(),
            verifier,
        );
        let account = account.exchange_client_credentials().await?;
        Ok(Self {
            keycloak_account: account.start_auto_refresh(),
            keycloak_base_url,
        })
    }
}

impl keycloak::KeycloakTokenSupplier for TokenSupplier {
    fn get<'life0, 'life1, 'async_trait>(
        &'life0 self,
        url: &'life1 str,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<String, keycloak::KeycloakError>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            // Enforce the trailing slash for the comparison down below.
            // Otherwise we risk panicking if the `url` does not have one despite the urls in general being identical.
            let keycloak_base_url: crate::oidc::url::Url = enforce_trailing_slash(
                url.parse()
                    .unwrap_or_else(|err| panic!("Cannot parse url '{url}': {err}")),
            )
            .expect("Keycloak base url passed to KeycloakTokenSupplier::get");
            if keycloak_base_url != self.keycloak_base_url {
                panic!(
                    "Can only serve keycloak base URL '{}', requested '{keycloak_base_url}'.",
                    self.keycloak_base_url
                );
            }
            Ok(self
                .keycloak_account
                .get_access_token()
                .await
                .expect("Cannot get token"))
        })
    }
}

#[cfg(test)]
mod tests {
    mod enforce_trailing_slash {
        use super::super::{UrlIsCannotBeABase, enforce_trailing_slash};

        fn url(url: impl Into<String>) -> crate::oidc::url::Url {
            url.into().parse().unwrap()
        }

        #[test]
        fn trailing_slashes() {
            assert_eq!(
                enforce_trailing_slash(url("http://localhost/a")).unwrap(),
                url("http://localhost/a/")
            );
            assert_eq!(
                enforce_trailing_slash(url("http://localhost/a/")).unwrap(),
                url("http://localhost/a/")
            );
            assert_eq!(
                enforce_trailing_slash(url("http://localhost/a//")).unwrap(),
                url("http://localhost/a//")
            );
        }

        #[test]
        fn cannot_be_a_base() {
            assert!(matches!(
                enforce_trailing_slash(url("mailto:me@example.com")).unwrap_err(),
                UrlIsCannotBeABase { url: received_url } if received_url == url("mailto:me@example.com")
            ));
        }
    }
}
