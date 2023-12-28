use std::sync::Arc;

use crate::{AppError, SessionDocument, SharedState, COL_USER_SESS, COOKIE_SESSION, DB_SESSIONS};
use anyhow::anyhow;
use axum::{
    extract::{Request, State, FromRequest},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};


use axum_extra::extract::{CookieJar, self};
use mongodb::{bson::doc, Client};
use serde::{Deserialize, Serialize};

use core::result::Result::Ok;

// I'm going to have to refactor "validate_session" from an axum middleware into a simple function that takes the cookie and the email that I will run at the beginning of each handler that requires auth.

// This is because the JSON extractor consumes the request, therefore it cannot be used in the middleware unless I clone the Request which is not possible since Request doesn't implement the clone trait for whatever reason.

pub async fn validate_session(
    client: &Client,
    user_email: &String,

    jar: &CookieJar,
) -> Result<(), anyhow::Error> {
     if let Some(sess_id) = jar.get(COOKIE_SESSION) {
        if let Ok(uuid) = uuid::Uuid::parse_str(sess_id.value())  {
        let res = client
            .database(DB_SESSIONS)
            .collection::<SessionDocument>(COL_USER_SESS)
            .find_one(doc! {"_id": uuid}, None)
            .await?;
      
            if let Some(query_res) = res {
                if &query_res.user_email == user_email {
                    return Ok(());
                }
            }
        };
    } 
    return Err(anyhow!("nice try bro"));
}
