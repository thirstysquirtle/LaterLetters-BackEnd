use std::sync::Arc;

use crate::{AppError, SessionDocument, SharedState, COL_USER_SESS, COOKIE_SESSION, DB_SESSIONS};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};


use axum_extra::extract::CookieJar;
use mongodb::bson::doc;
use serde::Deserialize;

use core::result::Result::Ok;

#[derive(Deserialize)]
struct EmailJson {
    email: String,
}

async fn validate_session(
    jar: CookieJar,
    Json(user_email_json): Json<EmailJson>,
    state: State<Arc<SharedState>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let client = &state.mongo_client;
    if let Some(sess_id) = jar.get(COOKIE_SESSION) {
        let uuid = match uuid::Uuid::parse_str(sess_id.value()) {
            Ok(res) => res,
            Err(_) => {
                return Ok((
                    StatusCode::UNAUTHORIZED,
                    [(header::SET_COOKIE, "".to_string())],
                ))
            }
        };

        let res = client
            .database(DB_SESSIONS)
            .collection::<SessionDocument>(COL_USER_SESS)
            .find_one(doc! {"_id": uuid}, None)
            .await?;
        match res {
            None => {
                return Ok((
                    StatusCode::UNAUTHORIZED,
                    [(header::SET_COOKIE, "".to_string())],
                ))
            }
            Some(query_res) => {
                if query_res.user_email == user_email_json.email {
                    let resp = next.run(request).await?;
                    return Ok(resp);
                }
            }
        };
    }
}
