use std::marker::PhantomData;

use axum::{
    extract::Request,
    response::{IntoResponse, Response},
};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Type alias for a pinned, boxed future with Send + static lifetime.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait IdPProvider<AC, IC, APM>
where
    AC: openidconnect::AdditionalClaims + Send + Sync,
    IC: openidconnect::AdditionalClaims + Send + Sync,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
{
    fn get_oidc_rp_verifier(&self) -> crate::verifier::Verifier<AC, IC, APM>;
}

#[derive(Clone)]
pub struct OIDCAuthenticationLayer<IdPP, AC, IC, APM>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Send + Sync,
    IC: openidconnect::AdditionalClaims + Send + Sync,
    IdPP: IdPProvider<AC, IC, APM> + Clone + Send + Sync + 'static,
{
    state: IdPP,
    ac: std::marker::PhantomData<AC>,
    ic: std::marker::PhantomData<IC>,
    apm: std::marker::PhantomData<APM>,
}

impl<IdPP, AC, IC, APM> OIDCAuthenticationLayer<IdPP, AC, IC, APM>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Send + Sync,
    IC: openidconnect::AdditionalClaims + Send + Sync,
    IdPP: IdPProvider<AC, IC, APM> + Clone + Send + Sync + 'static,
{
    pub fn new(state: IdPP) -> Self {
        Self {
            state: state,
            ac: std::marker::PhantomData,
            ic: std::marker::PhantomData,
            apm: std::marker::PhantomData,
        }
    }
}

impl<S, IdPP, AC, IC, APM> Layer<S> for OIDCAuthenticationLayer<IdPP, AC, IC, APM>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Send + Sync,
    IC: openidconnect::AdditionalClaims + Send + Sync,
    IdPP: IdPProvider<AC, IC, APM> + Clone + Send + Sync + 'static,
{
    type Service = OIDCAuthenticationService<S, IdPP, AC, IC, APM>;

    fn layer(&self, inner: S) -> Self::Service {
        OIDCAuthenticationService {
            inner,
            state: self.state.clone(),
            ac: PhantomData,
            ic: PhantomData,
            apm: PhantomData,
        }
    }
}

/// Tower middleware that wraps an inner service, verifying OIDC access tokens
/// from the `Authorization` header before delegating to the inner service.
#[derive(Clone)]
pub struct OIDCAuthenticationService<S, IdPP, AC, IC, APM>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
{
    inner: S,
    state: IdPP,
    ac: PhantomData<AC>,
    ic: PhantomData<IC>,
    apm: PhantomData<APM>,
}

impl<S, Resp, IdPP, AC, IC, APM> Service<Request<axum::body::Body>>
    for OIDCAuthenticationService<S, IdPP, AC, IC, APM>
where
    S: Service<Request<axum::body::Body>, Response = Resp> + Send + 'static,
    <S as Service<Request<axum::body::Body>>>::Future: Send + 'static,
    Resp: IntoResponse + Send,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Send + Sync,
    IC: openidconnect::AdditionalClaims + Send + Sync,
    IdPP: IdPProvider<AC, IC, APM> + Clone + Send + Sync + 'static,
{
    /// Always return `Response<Body>` so both the auth-success and auth-failure
    /// paths have a unified type. The inner service's response is converted via
    /// `.into_response()` to match when verification succeeds.
    type Response = Response<axum::body::Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Verify the OIDC access token from the `Authorization` header.
    ///
    /// Fixed behaviour:
    /// - **Missing header** → short-circuits with `401 Unauthorized`.
    /// - **Invalid token** → short-circuits with `401 Unauthorized` (the original code silently fell through to the inner service).
    /// - **Valid token** → passes control to the inner service, converting its response to `Response<Body>`.
    fn call(&mut self, req: Request<axum::body::Body>) -> Self::Future {
        let state = self.state.clone();
        let auth_header_opt = req
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(String::from);

        // Obtain the inner future outside the async block so we don't borrow `self` for `'static`.
        let inner_fut = self.inner.call(req);

        Box::pin(async move {
            if let Some(auth_header_str) = auth_header_opt {
                let verifier = state.get_oidc_rp_verifier();
                match verifier
                    .verify_access_token_strip_bearer(&auth_header_str)
                    .await
                {
                    Ok(_token) => {
                        tracing::trace!("OIDC access token verified successfully");
                        // Verification succeeded: pass through to the inner service.
                        let resp = inner_fut.await?;
                        Ok(resp.into_response())
                    }
                    Err(e) => {
                        tracing::warn!("OIDC access token verification failed: {}", e);
                        Ok(Response::builder()
                            .status(axum::http::StatusCode::UNAUTHORIZED)
                            .body(axum::body::Body::from("Unauthorized"))
                            .unwrap())
                    }
                }
            } else {
                tracing::debug!("No access token found!");
                Ok(Response::builder()
                    .status(axum::http::StatusCode::UNAUTHORIZED)
                    .body(axum::body::Body::from("Missing authentication token"))
                    .unwrap())
            }
        })
    }
}
