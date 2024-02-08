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
use chrono::Utc;
use mongodb::{bson::doc, change_stream::session, Client, Collection};
use serde::{Deserialize, Serialize};

use core::result::Result::Ok;

//OMG WTF SERDE HAS BEEN THE CAUSE OF THIS!!!! >:(
#[derive(Serialize, Deserialize)]
struct idk {
    _id: mongodb::bson::Uuid,
    user_email: String,
}

pub async fn auth_headers(
    state: State<Arc<SharedState>>,
    headers: HeaderMap,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    if let Some(sess_id) = jar.get(COOKIE_SESSION) {
        println!("cookie: {}", sess_id.value());
        if let Some(headerVal) = headers.get(EMAIL_HEADER) {
            if let Ok(email) = headerVal.to_str() {
                println!("Email: {email}");
                if let Ok(uuid) = mongodb::bson::Uuid::parse_str(sess_id.value()) {
                    let session_coll: Collection<idk> = state
                        .mongo_client
                        .database(DB_SESSIONS)
                        .collection(COL_USER_SESS);

                    let res = session_coll.find_one(doc!{"_id": uuid}, None).await;
                    // println!("asdas{}", );
                    match res {
                        Ok(brah) => {
                            if let Some(bruh) = brah {
                                println!("{}", bruh.user_email);
                                if &bruh.user_email == email {
                                    println!("{}", &bruh.user_email);
                                    let res = next.run(request).await;
                                    return res;
                                } else {
                                    println!("WFDASDAS");
                                }
                            } else {
                                println!("damn");
                            }
                        }
                        Err(err) => {
                            println!("2 {:#?}", err)
                        }
                    }
                };
            }
        }
    }
    println!("bruh");
    return StatusCode::UNAUTHORIZED.into_response();
}
