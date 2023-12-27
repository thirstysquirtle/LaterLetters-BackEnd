use crate::{AppError, SharedState, DB_USER};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use core::result::Result::Ok;
use mongodb::{
    bson::{bson, doc, Bson, Document},
    options::UpdateOptions,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_set, HashMap},
    sync::Arc,
};

static DB_USER_LETTERS: &str = "user_letters";
static COL_USER_TAGS: &str = "tags_per_user";

// region: ↓ Save a Letter↓
#[derive(Deserialize, Serialize)]
struct SaveLetterPayload {
    email: String,
    letter: LetterDocument,
}
#[derive(Deserialize, Serialize)]
struct LetterDocument {
    body: String,
    //The key is the TagId which is a composite of the name + color
    tag_list: HashMap<String, Tag>,
}
#[derive(Deserialize, Serialize)]
struct Tag {
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
    client
        .database(DB_USER_LETTERS)
        .collection(&payload.email)
        .insert_one(payload.letter, None)
        .await?;

    let set_doc = Document::new();
    let inc_doc = Document::new();
    for (&id, &tag) in payload.letter.tag_list.iter() {
        set_doc.insert(&id, 
            doc! {"name": tag.name, "color": tag.color});
        inc_doc.insert(format!("{}.count", tag.name), 1);
    }
    let update_doc = doc! {
        "$set": set_doc,
        "$inc": inc_doc
    };

    client
        .database(DB_USER)
        .collection(COL_USER_TAGS)
        .update_one(
            doc! {"_id": payload.email},
            update_doc,
            UpdateOptions::builder().upsert(true).build(),
        )
        .await?;

    Ok(())
}
// endregion: ↑Save a Letter↑

pub fn build(shared_state: Arc<SharedState>) -> Router {
    Router::new().with_state(shared_state)
}
