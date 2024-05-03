use leptos::{SignalGet, SignalGetUntracked};

#[leptos::server(AddTodo, "/api")]
pub async fn update_counter(counter: i32) -> Result<(), leptos::ServerFnError> {
    println!("Update counter request: {counter:?}");
    Ok(())
}

#[leptos::component]
pub fn OidcExample() -> impl leptos::IntoView {
    // Creates a reactive value to update the button
    let (count, set_count) = leptos::create_signal(0);
    let (state, set_state) = leptos::create_signal("".to_string());
    let on_click = move |_| {
        leptos::SignalUpdate::update(&set_count, |count| *count += 1);
        leptos::spawn_local(async move {
            update_counter(count.get_untracked()).await.unwrap();
        });
        let auth: oidc_rp::integrations::leptos::ClientAuth<
            oidc_rp::idp::EmptyAdditionalIdPMetadata,
        > = oidc_rp::integrations::leptos::ClientAuth::from_context();

        leptos::SignalUpdate::update(&set_state, |state| {
            *state = format!(
                "test {:?} {:?}",
                count.get_untracked(),
                auth.resource.get().unwrap().unwrap() // auth.resource.get().unwrap().unwrap().get_access_token()
            )
        });
    };

    leptos::view! {
        <h1>"Welcome to Leptos with oidc-rp!"</h1>
        <p>"(State = " {state}")"</p>
        <button on:click=on_click>"Click Me: " {count}</button>
    }
}
