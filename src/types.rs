// #[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
// pub struct BrownieOidcClientResourceAccess {
//     roles: Option<Vec<String>>,
// }

// #[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
// pub struct BrownieOidcAdditionalClaims {
//     #[serde(
//         default,
//         // Making this variable configurable is not an easy task as it would require to write own serializer and deserializer objects.
//         // See https://github.com/rust-lang/rust/issues/52393
//         // and https://github.com/serde-rs/serde/issues/1686
//         skip_serializing_if = "Option::is_none"
//     )]
//     resource_access: Option<HashMap<String, BrownieOidcClientResourceAccess>>,
// }
// impl AdditionalClaims for BrownieOidcAdditionalClaims {}

// impl BrownieOidcAdditionalClaims {
//     /// Returns user client roles. If none are set returns `None`
//     fn get_user_client_roles(&self) -> Result<Option<&Vec<String>>> {
//         if let Some(resource_access_val) = &self.resource_access {
//             let (_issuer_id, client_id) = get_oidc_env_settings().context("Unable to get oidc settings")?;
//             if let Some(resource_access) = resource_access_val.get(&client_id) {
//                 if let Some(roles_val) = &resource_access.roles {
//                     return Ok(Some(roles_val));
//                 } else {
//                     log::info!("No roles in resource_access.{client_id:?} claim in access token found");
//                 }
//             } else {
//                 log::info!("No item for client id {client_id:?} found in resource_access claim in access token");
//             }
//         } else {
//             log::info!("No resource_access claim found in access token");
//         }
//         Ok(None)
//     }
// }

// Token types
use openidconnect::new_type;

openidconnect::new_type![
    /// Audience claim value.
    #[derive(serde::Deserialize, Hash, Ord, PartialOrd, serde::Serialize)]
    Sub(String)
];

openidconnect::new_type![
    /// Audience claim value.
    #[derive(serde::Deserialize, Hash, Ord, PartialOrd, serde::Serialize)]
    JWTId(String)
];
