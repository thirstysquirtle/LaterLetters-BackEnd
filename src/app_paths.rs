use crate::{
    constants::{COL_USER_TAGS, DB_USER_LETTERS, EMAIL_HEADER},
    my_middleware, AppError, SessionDocument, SharedState, COL_USER_SESS, COOKIE_SESSION,
    DB_SESSIONS, DB_USER,
};
use anyhow::anyhow;
use axum::{
    extract::{Json, Path, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use axum_extra::extract::CookieJar;
use core::result::Result::Ok;
use futures::stream::{StreamExt, TryStream, TryStreamExt};
use mongodb::{
    bson::{bson, doc, Bson, Document, Uuid},
    options::UpdateOptions,
    Client, IndexModel,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_set, HashMap},
    fmt::format,
    hash::Hash,
    sync::Arc,
};

// region: ↓ Save a Letter↓

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
    tag_ids: Vec<String>, //This Vec is for MongoDB multiindex and will be derived from the keys of the Map
}
#[derive(Deserialize, Serialize, Clone)]
struct TagPayload {
    name: String,
    color: String,
}
#[derive(Deserialize, Serialize)]
struct DontCare {}
// POST - /letters
async fn save_letter(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(payload): Json<LetterPayload>,
) -> Result<impl IntoResponse, AppError> {
    let email = headers
        .get(EMAIL_HEADER)
        .expect("This should have been handle by middleware")
        .to_str()
        .expect("bru");
    let client = &state.mongo_client;
    if payload.body.len() > 10000 {
        return Ok(StatusCode::PAYLOAD_TOO_LARGE);
    };
    let mut tag_ids = Vec::with_capacity(payload.tag_list.len());
    for (key, _) in payload.tag_list.iter() {
        tag_ids.push(key.clone());
    }
    let doc_to_insert = LetterDocument {
        tag_ids: tag_ids,
        tag_list: payload.tag_list.clone(),
        body: payload.body,
    };
    let user_letter_collection = client.database(DB_USER_LETTERS).collection(email);

    user_letter_collection
        .create_index(
            IndexModel::builder().keys(doc! {"tag_ids": 1}).build(),
            None,
        )
        .await?;
    user_letter_collection
        .insert_one(doc_to_insert, None)
        .await?;

    let mut set_doc = Document::new();
    let mut inc_doc = Document::new();
    for (id, tag) in payload.tag_list.into_iter() {
        set_doc.insert(format!("{}.color", &id), &tag.color);
        set_doc.insert(format!("{}.name", &id), &tag.name);
        inc_doc.insert(format!("{}.count", id), 1);
    }
    inc_doc.insert("total_count", 1);
    // let update_doc = doc! {
    //     "$inc": inc_doc,
    //     "$set": set_doc,
    // };

    client
        .database(DB_USER)
        .collection::<DontCare>(COL_USER_TAGS)
        .update_one(
            doc! {"_id": email},
            doc! {"$set": set_doc},
            UpdateOptions::builder().upsert(true).build(),
        )
        .await?;

    client
        .database(DB_USER)
        .collection::<DontCare>(COL_USER_TAGS)
        .update_one(
            doc! {"_id": email},
            doc! {
                "$inc": inc_doc
            },
            UpdateOptions::builder().upsert(true).build(),
        )
        .await?;

    Ok(StatusCode::OK)
}
// endregion: ↑ Save a Letter ↑

// region: ↓ Query Letters ↓

#[derive(Deserialize, Serialize)]
struct TagResponse {
    name: String,
    color: String,
    count: u32,
}
#[derive(Deserialize, Serialize)]
struct TagsDoc {
    //Email or random ID
    _id: String,
    total_count: u32,

    #[serde(flatten)]
    unknown_fields: HashMap<String, TagResponse>,
}

// Get /tags
async fn query_user_tags(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
) -> Result<Json<TagsDoc>, AppError> {
    if let Some(email) = headers.get(EMAIL_HEADER) {
        let bru = email.to_str().expect("bru");
        let res = state
            .mongo_client
            .database(DB_USER)
            .collection::<TagsDoc>(COL_USER_TAGS)
            .find_one(doc! {"_id": bru}, None)
            .await?;
        match res {
            Some(obj) => return Ok(Json(obj)),
            None => return Err(AppError(anyhow!("No Doc"))),
        }
    }
    // return Ok(Json(res))

    Err(AppError(anyhow!("Not supposed to happens")))
}

// Get /letters
async fn query_all_letters(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<LetterDocument>>, AppError> {
    if let Some(email) = headers.get(EMAIL_HEADER) {
        let cursor = state
            .mongo_client
            .database(DB_USER_LETTERS)
            .collection::<LetterDocument>(email.to_str().expect("im gettin bored"))
            .find(None, None)
            .await?;

        return Ok(Json(cursor.try_collect().await?));
    }
    Err(AppError(anyhow!("Not supposed to Happen")))
}

// Get /letters/:tag_id
async fn query_letters_in_a_tag(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Path(tag_id): Path<String>,
) -> Result<Json<Vec<LetterDocument>>, AppError> {
    if let Some(email) = headers.get(EMAIL_HEADER) {
        let email = email.to_str().expect("idk");
        let cursor = state
            .mongo_client
            .database(DB_USER_LETTERS)
            .collection::<LetterDocument>(email)
            .find(doc! {"tag_ids": {"$all": [tag_id]}}, None)
            .await?;

        return Ok(Json(cursor.try_collect().await?));
    }
    return Err(AppError(anyhow!("Sumting wong")));
}
// endregion: ↑ Query Letters ↑

// region: ↓ Delete Actions ↓

// DEL /letters/:letter_id
async fn delete_letter(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Path(letter_id): Path<String>,
) -> Result<StatusCode, AppError> {
    if let Some(email) = headers.get(EMAIL_HEADER) {
        let email = email.to_str().expect("bored");
        let res = state
            .mongo_client
            .database(DB_USER_LETTERS)
            .collection::<LetterDocument>(email)
            .find_one_and_delete(doc! {"_id": &letter_id}, None)
            .await?;
        if let Some(del_letter) = res {
            let mut set_update_doc = Document::new();
            for tag in del_letter.tag_ids.iter() {
                set_update_doc.insert(
                    tag.clone(),
                    doc! {
                        "$cond": {
                            "if": { "$gt": [format!("${}", *tag), 0] }, // Check if the field is greater than 0
                            "then": { "$subtract": [format!("${}", *tag), 1] }, // Decrement the field by 1
                            "else": "$$REMOVE" // Remove the field if the value is 0 or less
                        }
                    },
                );
            }

            state
                .mongo_client
                .database(DB_USER)
                .collection::<DontCare>(COL_USER_TAGS)
                .update_one(
                    doc! {"_id": email },
                    doc! {"$set": set_update_doc, "$inc": {"total_count": -1} },
                    None,
                )
                .await?;
        }
        return Ok(StatusCode::OK);
    }
    Ok(StatusCode::IM_A_TEAPOT)
}

// DEL /tags/:tag_id
async fn delete_tag(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Path(tag_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(email) = headers.get(EMAIL_HEADER) {
        let email = email.to_str().expect("bored");
        state
            .mongo_client
            .database(DB_USER)
            .collection::<DontCare>(COL_USER_TAGS)
            .update_one(doc! { "_id": email }, doc! { "$unset": &tag_id}, None)
            .await?;

        state
            .mongo_client
            .database(DB_USER_LETTERS)
            .collection::<LetterDocument>(email)
            .update_many(
                doc! {"tag_ids": {"$all": &tag_id}},
                doc! {"$pull": {"tag_ids": &tag_id}},
                None,
            )
            .await?;

        return Ok(StatusCode::OK);
    }
    Ok(StatusCode::IM_A_TEAPOT)
}

// Del /letters/:tag_id
async fn delete_tagged_letters(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Path(tag_id): Path<String>,
) -> Result<StatusCode, AppError> {
    if let Some(header_val) = headers.get(EMAIL_HEADER) {
        if let Ok(email) = header_val.to_str() {
            let res = state
                .mongo_client
                .database(DB_USER_LETTERS)
                .collection::<LetterDocument>(email)
                .delete_many(doc! {"tag_ids": {"$all": &tag_id}}, None)
                .await?;

            state
                .mongo_client
                .database(DB_USER)
                .collection::<DontCare>(COL_USER_TAGS)
                .update_one(
                    doc! { "_id": email },
                    doc! { "$unset": &tag_id, "$inc": {"total_count": (0 - res.deleted_count as u32)}},
                    None,
            )
        .await?;

            return Ok(StatusCode::OK);
        }
    }
    return Ok(StatusCode::IM_A_TEAPOT);
}

// endregion: ↑ Delete Actions ↑

pub fn build(shared_state: Arc<SharedState>) -> Router {
    Router::new()
        .route("/letters", get(query_all_letters).post(save_letter))
        .route(
            "/letters/:tag_id",
            get(query_letters_in_a_tag).delete(delete_tagged_letters),
        )
        .route("/letter/:letter_id", delete(delete_letter))
        .route("/tags/:tag_id", delete(delete_tag))
        .route("/tags", get(query_user_tags))
        .route_layer(middleware::from_fn_with_state(
            shared_state.clone(),
            my_middleware::auth_headers,
        ))
        .with_state(shared_state)
}
