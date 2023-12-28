use crate::{
    my_middleware, AppError, SessionDocument, SharedState, COL_USER_SESS, COOKIE_SESSION,
    DB_SESSIONS, DB_USER, constants::{DB_USER_LETTERS, COL_USER_TAGS},
};
use anyhow::anyhow;
use axum::{
    extract::{Json, Request, State},
    http::{ StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use axum_extra::extract::CookieJar;
use core::result::Result::Ok;
use futures::stream::{StreamExt, TryStreamExt, TryStream};
use mongodb::{
    bson::{bson, doc, Bson, Document},
    options::UpdateOptions,
    Client, IndexModel,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_set, HashMap},
    sync::Arc,
};



// region: ↓ Save a Letter↓
#[derive(Deserialize)]
struct SaveLetterPayload {
    email: String,
    letter: LetterPayload,
}
#[derive(Deserialize, Clone)]
struct LetterPayload {
    body: String,
    //The key is the TagId which is a composite of the name + color
    tag_list: HashMap<String, TagPayload>,
}
#[derive(Serialize, Deserialize)]
pub struct LetterDocument {
    body: String,
    //The key is the TagId which is a composite of the name + color
    tag_list: HashMap<String, TagPayload>, 
    tag_ids: Vec<String>
    //This Vec is for MongoDB multiindex and will be derived from the keys of the Map
}
#[derive(Deserialize, Serialize, Clone)]
struct TagPayload {
    name: String,
    color: String,
}
#[derive(Deserialize, Serialize)]
struct DontCare {}

async fn save_letter(
    State(state): State<Arc<SharedState>>,
    jar: CookieJar,
    Json(payload): Json<SaveLetterPayload>,
) -> Result<impl IntoResponse, AppError> {
    let client = &state.mongo_client;
    my_middleware::validate_session(&client, &payload.email, &jar).await?;
    if payload.letter.body.len() > 10000 {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let mut tag_ids = Vec::with_capacity(payload.letter.tag_list.len());
    for (key, _) in payload.letter.tag_list.iter() {
        tag_ids.push(key.clone());
    }
    let doc_to_insert = LetterDocument {
        tag_ids: tag_ids,
        tag_list: payload.letter.tag_list.clone(),
        body: payload.letter.body
    };
    let user_letter_collection = client.database(DB_USER_LETTERS).collection(&payload.email);

    user_letter_collection.create_index(IndexModel::builder().keys(doc! {"tag_ids": 1}).build(), None).await?;
    user_letter_collection.insert_one(doc_to_insert, None).await?;
    

    let mut set_doc = Document::new();
    let mut inc_doc = Document::new();
    for (id, tag) in payload.letter.tag_list.into_iter() {
        set_doc.insert(&id, doc! {"name": &tag.name, "color": tag.color});
        inc_doc.insert(format!("{}.count", tag.name), 1);
    }
    let update_doc = doc! {
        "$set": set_doc,
        "$inc": inc_doc
    };

    client
        .database(DB_USER)
        .collection::<DontCare>(COL_USER_TAGS)
        .update_one(
            doc! {"_id": payload.email},
            update_doc,
            UpdateOptions::builder().upsert(true).build(),
        )
        .await?;

    Ok(StatusCode::OK)
}
// endregion: ↑ Save a Letter ↑

// region: ↓ Query Letters ↓

#[derive(Deserialize)]
struct EmailPayload {
    email: String,
}

#[derive(Deserialize)]
struct TagResponse {
    name: String,
    color: String,
    count: u32,
}
async fn query_user_tags(
    State(state): State<Arc<SharedState>>,
    jar: CookieJar,
    Json(payload): Json<EmailPayload>,
) -> Result<Json<HashMap<String, TagResponse>>, AppError> {
    my_middleware::validate_session(&state.mongo_client, &payload.email, &jar).await?;
    let res = state
        .mongo_client
        .database(DB_USER)
        .collection::<HashMap<String, TagResponse>>(COL_USER_TAGS)
        .find_one(doc! {"_id": payload.email}, None)
        .await?;
    match res {
        Some(obj) => Ok(Json(obj)),
        None => Ok(Json(HashMap::new())),
    }
    // return Ok(Json(res))

    // Err(anyhow!("as").into())
}

async fn query_all_letters(
    State(state): State<Arc<SharedState>>,
    jar: CookieJar,
    Json(payload): Json<EmailPayload>,
) -> Result<Json<Vec<LetterDocument>>, AppError> {
    my_middleware::validate_session(&state.mongo_client, &payload.email, &jar).await?;
    let cursor = state
        .mongo_client
        .database(DB_USER_LETTERS)
        .collection::<LetterDocument>(&payload.email)
        .find(None, None)
        .await?;

    Ok(Json(cursor.try_collect().await?))
}

struct TaggedLettersPayload {
    email: String,
    tag: String
}
async fn query_letters_in_a_tag(
    State(state): State<Arc<SharedState>>,
    jar: CookieJar,
    Json(payload): Json<TaggedLettersPayload>,
) -> Result<Json<Vec<LetterDocument>>, AppError> {
    my_middleware::validate_session(&state.mongo_client, &payload.email, &jar).await?;
    let cursor = state.mongo_client.database(DB_USER_LETTERS).collection::<LetterDocument>(&payload.email).find(doc! {"tag_ids": {"$all": [payload.tag]}}, None).await?;

    Ok(Json(cursor.try_collect().await?))
}
// endregion: ↑ Query Letters ↑

// region: ↓ Delete Actions ↓
#[derive(Deserialize)]
struct DeleteLetterPayload {
    email: String,
    letter_id: [u8;12],
}

async fn delete_letter(
    State(state): State<Arc<SharedState>>,
    jar: CookieJar,
    Json(payload): Json<DeleteLetterPayload>,

) -> Result<impl IntoResponse, AppError> {
    my_middleware::validate_session(&state.mongo_client, &payload.email, &jar).await?;

    Ok(())

}
// endregion: ↑ Delete Actions ↑


fn build(shared_state: Arc<SharedState>) -> Router {
    Router::new()
        .route("/create", post(save_letter))
        .with_state(shared_state)
}
