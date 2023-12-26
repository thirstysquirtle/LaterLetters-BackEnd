use crate::{AppError, SharedState};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use core::result::Result::Ok;
use serde::{Deserialize, Serialize};
use std::{collections::hash_set, sync::Arc};
use mongodb::bson::doc;

static DB_USER_LETTERS: &str = "user_letters";
static COL_USER_TAGS: &str = "tags_per_user";

// region: ↓ Save a Letter↓
#[derive(Deserialize, Serialize)]
struct SaveLetterPayload {
    email: String,
    letter: LetterDocument   
}
#[derive(Deserialize, Serialize)]
struct LetterDocument {
    body: String,
    tag_list: Vec<Tag>,
}
#[derive(Deserialize, Serialize)]
struct Tag {
    //The ID is a composite name + color
    _id: String,
    name: String,
    color: String,
}

async fn save_letter(
    State(state): State<Arc<SharedState>>,
    Json(payload): Json<SaveLetterPayload>,
) -> Result<impl IntoResponse, AppError> {
    if payload.letter.body.len() > 10000 {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let client = &state.mongo_client;
    let res = client.database(DB_USER_LETTERS).collection(&payload.email).insert_one(payload.letter ,None).await?;
    

    Ok(())
}
// endregion: ↑Save a Letter↑

pub fn build(shared_state: Arc<SharedState>) -> Router {
    Router::new().with_state(shared_state)
}
