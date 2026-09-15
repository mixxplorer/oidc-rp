use axum::{
    Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

// Type alias for a pinned, boxed future with Send + static lifetime.
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
            ac: std::marker::PhantomData,
            ic: std::marker::PhantomData,
            apm: std::marker::PhantomData,
        }
    }
}

pub struct ResponseFuture<F> {
    inner: std::pin::Pin<Box<F>>,
}

impl<F, B, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Default,
{
    type Output = Result<Response<B>, E>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

#[derive(Clone)]
pub struct OIDCAuthenticationService<S, IdPP, AC, IC, APM>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
{
    inner: S,
    state: IdPP,
    ac: std::marker::PhantomData<AC>,
    ic: std::marker::PhantomData<IC>,
    apm: std::marker::PhantomData<APM>,
}

impl<S, B, IdPP, AC, IC, APM> Service<Request<B>>
    for OIDCAuthenticationService<S, IdPP, AC, IC, APM>
where
    S: Service<Request<B>>,
    <S as Service<Request<B>>>::Future: Send + 'static,
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
    AC: openidconnect::AdditionalClaims + Send + Sync,
    IC: openidconnect::AdditionalClaims + Send + Sync,
    IdPP: IdPProvider<AC, IC, APM> + Clone + Send + Sync + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let state = self.state.clone();
        let auth_header_opt = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_owned());

        // Obtain the inner future outside the async block so we don't borrow `self` for `'static`.
        let inner_fut = self.inner.call(req);

        Box::pin(async move {
            if let Some(auth_header_str) = auth_header_opt {
                let verifier = state.get_oidc_rp_verifier();
                if let Err(e) = verifier
                    .verify_access_token_strip_bearer(&auth_header_str)
                    .await
                {
                    eprintln!("OIDC access token verification failed: {}", e);
                }
            }
            inner_fut.await
        })
    }
}
