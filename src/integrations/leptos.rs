use leptos::{SignalGet, SignalGetUntracked};

#[derive(Debug, Clone)]
pub struct ClientAuth<APM = crate::idp::EmptyAdditionalIdPMetadata>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
{
    // pub account: Option<std::sync::Arc<crate::account::Account<APM, AreAccountTokenAvailable>>>,
    pub resource: leptos::Resource<
        Option<Option<crate::idp::IdPAttributesShare<APM>>>,
        Result<
            std::sync::Arc<crate::account::Account<APM, crate::types::AttributeSet>>,
            crate::wasm::WasmError,
        >,
    >,
}

impl<APM> ClientAuth<APM>
where
    APM: openidconnect::AdditionalProviderMetadata + PartialEq + Send + Sync + 'static,
{
    pub fn initialize<Fu>(
        callback_path: String,
        enforce_user: bool,
        initializer: impl Fn(Option<crate::idp::IdPAttributesShare<APM>>) -> Fu + Copy + 'static,
    ) where
        Fu: futures::Future<
                Output = Result<
                    crate::account::Account<APM, crate::types::AttributeNotSet>,
                    crate::wasm::WasmError,
                >,
            > + 'static,
    {
        // let callback_path_owned = std::sync::Arc::new(callback_path.to_string());
        // let callback_path_ref = &callback_path_owned;

        if !enforce_user {
            panic!("Not enforcing a user is currently not supported!");
        }

        // check whether we have to login the user (if enforce_uer is true)
        let metdata_resource: leptos::Resource<(), Option<crate::idp::IdPAttributesShare<APM>>> =
            leptos::create_resource(
                move || (),
                move |_| async move {
                    let account = initializer(None).await;

                    match account {
                        Ok(acc) => Some(acc.get_idp().state().await.unwrap()),
                        Err(_) => None,
                    }
                },
            );

        let resource = leptos::create_local_resource(
            move || metdata_resource.get(),
            move |metadata_resource| {
                // clone strings before moving out of context
                let callback_path = callback_path.clone();

                let inner_future = || async move {
                    match metadata_resource {
                        Some(cached_resources) => {
                            let account = initializer(cached_resources).await?;

                            // check whether we are on our callback route (and thus consume the token parameters, else redirect user)
                            let route = leptos_router::use_location().pathname.get_untracked();

                            let mut auth_required = route != callback_path;

                            if route == callback_path {
                                // leptos::logging::log!("callback path! route = {:?}", route);

                                match crate::wasm::exchange_pkce_token_from_url(account.clone())
                                    .await
                                {
                                    Ok((account_with_tokens, redirect_uri)) => {
                                        // we are successful! Now redirect the user back to the original route
                                        crate::wasm::verify_redirect_uri(&redirect_uri)?;

                                        // leptos_router::Redirect(leptos_router::RedirectProps { path: redirect_uri.path().to_string(), options: Some() });
                                        let navigate = leptos_router::use_navigate();
                                        navigate(
                                            redirect_uri.as_ref(),
                                            leptos_router::NavigateOptions {
                                                resolve: false,
                                                replace: true,
                                                scroll: false,
                                                ..Default::default()
                                            },
                                        );
                                        leptos::logging::debug_warn!(
                                            "Redirect to {:?} done!",
                                            redirect_uri.to_string()
                                        );
                                        return Ok(std::sync::Arc::new(account_with_tokens));
                                    }
                                    Err(error) => {
                                        leptos::logging::error!(
                                            "Error during executing callback: {error:?}"
                                        );
                                        match error {
                                            crate::wasm::WasmError::AuthenticationRequired() => {
                                                auth_required = true
                                            }
                                            crate::wasm::WasmError::QueryParamsMissing(_) => {
                                                auth_required = true
                                            }
                                            crate::wasm::WasmError::AuthStateMissing(_) => {
                                                auth_required = true
                                            }
                                            crate::wasm::WasmError::AuthStateInvalid(_) => {
                                                auth_required = true
                                            }
                                            _ => {
                                                // just do nothing and let the panic begin (return error)
                                            }
                                        }
                                    }
                                }
                            }
                            if enforce_user && auth_required {
                                let window_location = web_sys::window().unwrap().location();

                                let callback_url = url::Url::parse(&format!(
                                    "{}{}",
                                    window_location.protocol().unwrap(),
                                    window_location.host().unwrap()
                                ))
                                .unwrap()
                                .join(&callback_path)
                                .unwrap();

                                let (authorize_url, authorize_state) = account
                                    .authorize_url_pkce(
                                        vec!["openid".to_string()],
                                        callback_url,
                                        crate::wasm::get_current_uri()?,
                                    )
                                    .await
                                    .unwrap();

                                crate::wasm::store_authorize_state(authorize_state).unwrap();

                                web_sys::window()
                                    .unwrap()
                                    .location()
                                    .replace(authorize_url.as_str())
                                    .unwrap();
                                leptos::logging::debug_warn!("Redirecting to OIDC login!");
                            } else {
                                panic!("Not enforcing a user is currently not supported!")
                            }
                            Err(crate::wasm::WasmError::AuthenticationRequired())
                        }
                        None => {
                            leptos::logging::debug_warn!("Not loading authentication as fetching metadata is not finished right now.");
                            Err(crate::wasm::WasmError::NotReady("Not loading authentication as fetching metadata is not finished right now.".to_string()))
                        }
                    }
                };
                inner_future()
            },
        );

        let result = Self { resource };
        leptos::provide_context(result);
    }

    pub fn from_context() -> Self {
        leptos::use_context::<Self>().unwrap()
    }
}

///// Stub component showing content only if the authentication is still loading
// #[leptos::component]
// pub fn ClientAuthLoading() -> impl leptos::IntoView {
//     // Creates a reactive value to update the button
//     let (count, set_count) = leptos::create_signal(0);
//     let (state, set_state) = leptos::create_signal("".to_string());
//     let on_click = move |_| {
//         let auth: crate::integrations::leptos::ClientAuth<crate::idp::EmptyAdditionalIdPMetadata> =
//             crate::integrations::leptos::ClientAuth::from_context();
//     };

//     leptos::view! {
//         <h1>"Welcome to Leptos! (State = " {state}")"</h1>
//         <button on:click=on_click>"Click Me: " {count}</button>
//     }
// }
