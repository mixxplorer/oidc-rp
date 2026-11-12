pub(crate) fn get_default_reqwest_client_internal() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        // do not set redirect policy as this is handled by browser
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION"),
        ))
        .referer(false)
}

/// Provides a basic built client for further modifications.
///
/// This client contains most basic features, making the build available for further modifications, eg:
///
/// ```rust
/// # fn test() -> anyhow::Result<()> {
/// let builder = oidc_rp::reqwest_client::get_default_reqwest_client();
/// let builder = builder.timeout(std::time::Duration::from_secs(10));
/// let client = builder.build()?;
///
/// // Then use `client` to construct a new IdP or TokenSupplier object.
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "special-reqwest-client")]
pub fn get_default_reqwest_client() -> reqwest::ClientBuilder {
    get_default_reqwest_client_internal()
}
