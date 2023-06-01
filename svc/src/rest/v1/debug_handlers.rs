use std::env;

use actix_web::{
    get,
    web::{self, Data, Json},
    Scope,
};
use serde::Serialize;

use crate::{rest::api::ApiError, store::Store};

#[derive(Serialize)]
pub struct ReadinessResponse {
    status: String,
}

#[get("/readiness")]
pub async fn readiness(_store: Data<Store>) -> Result<Json<ReadinessResponse>, ApiError> {
    Ok(Json(ReadinessResponse {
        status: "ok".to_string(),
    }))
}

#[derive(Serialize)]
pub struct LivenessReponse {
    status: String,
    version: String,
    hostname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pod_ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    // max procs
}

#[get("/liveness")]
pub async fn liveness(_store: Data<Store>) -> Result<Json<LivenessReponse>, ApiError> {
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let hostname = sys_info::hostname().ok();
    let name = env::var("KUBERNETES_NAME").ok();
    let pod_ip = env::var("KUBERNETES_POD_IP").ok();
    let node = env::var("KUBERNETES_NODE_NAME").ok();
    let namespace = env::var("KUBERNETES_NAMESPACE").ok();

    Ok(Json(LivenessReponse {
        status: "ok".to_string(),
        version,
        hostname,
        name,
        pod_ip,
        node,
        namespace,
    }))
}

pub fn api() -> Scope {
    web::scope("/debug").service(readiness).service(liveness)
}
