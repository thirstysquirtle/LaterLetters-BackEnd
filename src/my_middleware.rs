use std::sync::Arc;

use crate::{
    constants::EMAIL_HEADER, AppError, SessionDocument, SharedState, COL_USER_SESS, COOKIE_SESSION,
    DB_SESSIONS,
};
use anyhow::anyhow;
use axum::{
    extract::{FromRequest, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::head,
    Json,
};

use axum_extra::extract::{self, CookieJar};
use mongodb::{bson::doc, Client};
use serde::{Deserialize, Serialize};

use core::result::Result::Ok;

pub async fn auth_headers(
    state: State<Arc<SharedState>>,
    headers: HeaderMap,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    if let Some(sess_id) = jar.get(COOKIE_SESSION) {
        if let Some(headerVal) = headers.get(EMAIL_HEADER) {
            if let Ok(email) = headerVal.to_str() {
                if let Ok(uuid) = uuid::Uuid::parse_str(sess_id.value()) {
                    let res = state
                        .mongo_client
                        .database(DB_SESSIONS)
                        .collection::<SessionDocument>(COL_USER_SESS)
                        .find_one(doc! {"_id": uuid}, None)
                        .await;

                    if let Ok(Some(query_res)) = res {
                        if &query_res.user_email == email {
                            let res = next.run(request).await;
                            return res;
                        }
                    }
                };
            }
        }
    }
    return StatusCode::UNAUTHORIZED.into_response();
}
