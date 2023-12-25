use crate::{SharedState, AppError};
use axum::{extract::{Json, State}, response::IntoResponse, http::StatusCode};
use serde::Deserialize;
use std::{sync::Arc, collections::hash_set};
use core::result::Result::Ok;

// region: ↓ Save a Letter↓
#[derive(Deserialize)]
struct SaveLetterPayload {
    email: String,
    body: String,
    tag_list: Vec<TagListPayload>,
}
#[derive(Deserialize)]
struct TagListPayload {
    //The ID is a composite name + color
    id: String,
    name: String,
    color: String,
}


async fn save_letter(
    State(state): State<Arc<SharedState>>,
    Json(payload): Json<SaveLetterPayload>,
) -> Result<impl IntoResponse, AppError> {
    if payload.body.len() > 10000 { return Ok(StatusCode::PAYLOAD_TOO_LARGE) };
    
 


    Ok(())
}
// endregion: ↑Save a Letter↑

pub fn build(shared_state: Arc<SharedState>) -> Router {
    Router::new().with_state(shared_state)
}


