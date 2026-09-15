#[derive(serde::Serialize, schemars::JsonSchema, aide::OperationIo)]
#[aide(output)]
pub struct GenericResponse {
    authenticated: bool,
}

#[derive(serde::Serialize, schemars::JsonSchema, aide::OperationIo)]
#[aide(output)]
pub struct HealthResponse {
    operational: bool,
}

pub fn health_desc(op: aide::transform::TransformOperation) -> aide::transform::TransformOperation {
    op.description("Returns whether the API is healthy")
        .id("health")
}

pub async fn health(
    axum::extract::State(_state): axum::extract::State<crate::AppState>,
) -> Result<axum::Json<HealthResponse>, crate::errors::WebAppError> {
    Ok(axum::Json(HealthResponse {
        operational: true, // as soon as the API is reachable, it is also operational
    }))
}

pub fn authenticated_desc(
    op: aide::transform::TransformOperation,
) -> aide::transform::TransformOperation {
    op.description("Checks whether a hash appeared in a known credential leak.")
        .id("checkHash")
}

pub async fn authenticated(
    axum::extract::State(_state): axum::extract::State<crate::AppState>,
) -> Result<axum::Json<GenericResponse>, crate::errors::WebAppError> {
    Ok(axum::Json(GenericResponse {
        authenticated: true,
    }))
}
