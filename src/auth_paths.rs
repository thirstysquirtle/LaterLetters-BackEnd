// This code sucks in terms of DRY and maintainabality, but I'm too uninterested to refactor it for now. 5 Jan 2023
use anyhow::anyhow;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use axum_extra::extract::cookie::{self, CookieJar};
use std::{error::Error, ops::Add, sync::Arc};

use crate::{
    AppError, SessionDocument, SharedState, COL_PASSWORD_RESET, COL_USER_CREDS, COL_USER_SESS,
    COOKIE_SESSION, DB_SESSIONS, DB_USER, constants::COOKIE_EMAIL,
};
use chrono::{Days, Utc};
use mongodb::bson::{doc};
use serde::{Deserialize, Serialize};

use tokio::{
    join,
    time::{sleep, Duration},
};

#[derive(Deserialize)]
struct UserLoginCredentials {
    email: String,
    password: Option<String>,
}

pub fn setCookieHeaders(sess_id: &str, username: &str) -> HeaderMap {
    let sess_cook = cookie::Cookie::build((COOKIE_SESSION, sess_id))
        .http_only(true)
        .path("/");
    let username_cook = cookie::Cookie::build((COOKIE_EMAIL, username))
        .path("/");
    let mut header = HeaderMap::new();
    header.append(header::SET_COOKIE, HeaderValue::from_str( &sess_cook.to_string()).unwrap());
    header.append(header::SET_COOKIE,  HeaderValue::from_str( &username_cook.to_string()).unwrap());

    return header;
}

#[derive(Serialize, Deserialize)]
struct UserDocument {
    //the id is their Email/Username
    _id: String,
    pass_hash: String,
}

async fn login_user(
    State(state): State<Arc<SharedState>>,
    Json(user_creds): Json<UserLoginCredentials>,
) -> Result<impl IntoResponse, AppError> {
    if user_creds.email.len() > 256 {
        return Ok((StatusCode::PAYLOAD_TOO_LARGE, setCookieHeaders("", "")));
    }

    let anti_timing_attacks = sleep(Duration::from_millis(550));
    let handler = async {
        let client = &state.mongo_client;
        let argo = Argon2::default();

        let query_res = client
            .database(DB_USER)
            .collection::<UserDocument>(COL_USER_CREDS)
            .find_one(doc! {"_id": &user_creds.email}, None)
            .await;
        if let Ok(Some(user_acc)) = query_res {
            let hash = match PasswordHash::new(&user_acc.pass_hash) {
                Ok(hash) => hash,
                Err(_) => return Err(AppError(anyhow::anyhow!("wut"))),
            };

            if let None = user_creds.password {
                return Err(AppError::from(anyhow!("no password bru")));
            }
            match argo.verify_password(user_creds.password.unwrap().as_bytes(), &hash) {
                Ok(_) => {
                    let sess_id = mongodb::bson::Uuid::from(uuid::Uuid::new_v4());
                    client
                        .database(DB_SESSIONS)
                        .collection(COL_USER_SESS)
                        .insert_one(
                            doc! {
                                "_id": sess_id,
                                "user_email": &user_creds.email,
                                "expiry_date": Utc::now().add(Days::new(30)),
                            },
                            None,
                        )
                        .await?;

                    // let cook = Cookie::build((COOKIE_SESSION, sess_id.to_string()))
                    // .path("/")
                    // .http_only(true);
                    return Ok((
                        StatusCode::OK,
                        setCookieHeaders(&sess_id.to_string(), &user_creds.email),
                    ));
                }
                Err(_) => return Ok((StatusCode::UNAUTHORIZED, setCookieHeaders("", ""))),
            }
        } else {
            return Ok((StatusCode::UNAUTHORIZED, setCookieHeaders("", "")));
        }
    };
    join!(handler, anti_timing_attacks).0
}

async fn register_user(
    State(state): State<Arc<SharedState>>,
    Json(user_creds): Json<UserLoginCredentials>,
) -> Result<impl IntoResponse, AppError> {
    if user_creds.email.len() > 256 {
        return Ok((StatusCode::PAYLOAD_TOO_LARGE, setCookieHeaders("", "")));
    }
    let client = &state.mongo_client;
    let user_acc = client
        .database(DB_USER)
        .collection::<UserDocument>(COL_USER_CREDS)
        .find_one(doc! {"_id" : &user_creds.email}, None)
        .await;

    if let Ok(None) = user_acc {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        if let None = user_creds.password {
            return Err(AppError::from(anyhow!("no password bru")));
        }

        let password_hash =
            match argon2.hash_password(user_creds.password.unwrap().as_bytes(), &salt) {
                Ok(hash) => hash.to_string(),
                Err(_) => return Err(AppError(anyhow::anyhow!("wut"))),
            };
        client
            .database(DB_USER)
            .collection(COL_USER_CREDS)
            .insert_one(
                UserDocument {
                    _id: user_creds.email.clone(),
                    pass_hash: password_hash,
                },
                None,
            )
            .await?;
        let sess_id = mongodb::bson::Uuid::from(uuid::Uuid::new_v4());

        let sess_expiry = chrono::Utc::now().add(chrono::Days::new(30));
        client
            .database(DB_SESSIONS)
            .collection(COL_USER_SESS)
            .insert_one(
                doc! {
                    "_id": sess_id,
                    "expiry_date": sess_expiry,
                    "user_email": &user_creds.email,
                },
                None,
            )
            .await?;
        // let cook = Cookie::build((COOKIE_SESSION, sess_id.to_string()))
        // .path("/")
        // .http_only(true);
        Ok((
            StatusCode::OK,
            setCookieHeaders(&sess_id.to_string(), &user_creds.email),
        ))
    } else {
        Err(AppError(anyhow::anyhow!("wut")))
    }
}

async fn logout_user(
    State(state): State<Arc<SharedState>>,
    jar: CookieJar,
) -> Result<impl IntoResponse, AppError> {
    let client = &state.mongo_client;
    // let cook = Cookie::build((COOKIE_SESSION, "".to_string()))
    // .path("/")
    // .http_only(true);

    if let Some(sess_id) = jar.get(COOKIE_SESSION) {
        let uuid = match uuid::Uuid::parse_str(sess_id.value()) {
            Ok(res) => res,
            Err(_) => return Ok((StatusCode::IM_A_TEAPOT, setCookieHeaders("", ""))),
        };

        let res = client
            .database(DB_SESSIONS)
            .collection::<SessionDocument>(COL_USER_SESS)
            .delete_one(doc! {"_id": uuid}, None)
            .await?;
        if res.deleted_count == 1 {
            return Ok((StatusCode::OK, setCookieHeaders("", "")));
        }
    }
    Ok((StatusCode::IM_A_TEAPOT, setCookieHeaders("", "")))
}

async fn send_email_reset(
    State(state): State<Arc<SharedState>>,
    Json(user_creds): Json<UserLoginCredentials>,
) -> Result<impl IntoResponse, AppError> {
    let anti_timing_attacks = sleep(Duration::from_millis(550));
    let handler = async {
        let client = &state.mongo_client;

        let password_reset_token = mongodb::bson::Uuid::from(uuid::Uuid::new_v4());

        let expire_date = Utc::now().add(chrono::Duration::days(1));

        let user_acc = client
            .database(DB_USER)
            .collection::<UserDocument>(COL_USER_CREDS)
            .find_one(doc! {"_id": &user_creds.email}, None)
            .await?;
        if let None = user_acc {
            //"If you have an account with us, you will receive an email"
            return Ok(StatusCode::OK);
        }

        client
            .database(DB_SESSIONS)
            .collection(COL_PASSWORD_RESET)
            .insert_one(
                SessionDocument {
                    _id: password_reset_token.clone(),
                    expiry_date: expire_date,
                    user_email: user_creds.email.clone(),
                },
                None,
            )
            .await?;

        //send email
        let recipient = Destination::builder()
            .to_addresses(&user_creds.email)
            .build();
        let subject = Content::builder()
            .data("Reset Your Password")
            .build()
            .expect("Building Email");
        let body = Content::builder()
            .data(format! {"bruhhh {}", password_reset_token})
            .build()
            .expect("Building Email");
        let body = Body::builder().text(body).build();
        let email_content = EmailContent::builder()
            .simple(Message::builder().subject(subject).body(body).build())
            .build();

        let send_res = state
            .ses_client
            .send_email()
            .from_email_address("do-not-reply@sinnguyen.dev")
            .destination(recipient)
            .content(email_content)
            .send()
            .await;

        match send_res {
            Err(err) => {
                println!("{:?}", err.source());
                client
                    .database(DB_SESSIONS)
                    .collection::<SessionDocument>(COL_PASSWORD_RESET)
                    .delete_one(doc! {"_id": password_reset_token.to_string()}, None)
                    .await?;
                return Ok(StatusCode::SERVICE_UNAVAILABLE);
            }
            Ok(res) => {
                if let None = res.message_id {
                    println!("No Message ID from SES");
                    client
                        .database(DB_SESSIONS)
                        .collection::<SessionDocument>(COL_PASSWORD_RESET)
                        .delete_one(doc! {"_id": password_reset_token.to_string()}, None)
                        .await?;
                    return Ok(StatusCode::SERVICE_UNAVAILABLE);
                }
            }
        }
        Ok(StatusCode::OK)
    };
    join!(handler, anti_timing_attacks).0
}

#[derive(Deserialize)]
struct UserResetInfo {
    email: String,
    password: String,
    uuid: String,
}

async fn reset_password(
    State(state): State<Arc<SharedState>>,
    Json(user_reset): Json<UserResetInfo>,
) -> Result<impl IntoResponse, AppError> {
    let client = &state.mongo_client;
    let uuid = match uuid::Uuid::parse_str(&user_reset.uuid) {
        Ok(res) => res,
        Err(_) => return Ok(StatusCode::IM_A_TEAPOT),
    };
    let find_reset_by_uuid = doc! { "_id": uuid };
    let find_account_by_email = doc! {"_id": user_reset.email};
    let res = client
        .database(DB_SESSIONS)
        .collection::<SessionDocument>(COL_PASSWORD_RESET)
        .find_one(find_reset_by_uuid.clone(), None)
        .await?;
    if let None = res {
        return Ok(StatusCode::UNAUTHORIZED);
    }
    let res = res.unwrap();
    if Utc::now() > res.expiry_date {
        return Ok(StatusCode::UNAUTHORIZED);
    }

    let acc = client
        .database(DB_USER)
        .collection::<UserDocument>(COL_USER_CREDS)
        .find_one(find_account_by_email.clone(), None)
        .await?;

    if let None = acc {
        //This would only run if the account had been deleted, or I messed up the code
        return Ok(StatusCode::UNAUTHORIZED);
    }
    let password_hash = match Argon2::default().hash_password(
        user_reset.password.as_bytes(),
        &SaltString::generate(&mut OsRng),
    ) {
        Ok(hash) => hash.to_string(),
        Err(_) => return Err(AppError(anyhow::anyhow!("wut"))),
    };

    let update = doc! {"$set": doc! {"pass_hash": password_hash} };
    let update_res = client
        .database(DB_USER)
        .collection::<UserDocument>(COL_USER_CREDS)
        .update_one(find_account_by_email, update, None)
        .await?;
    if update_res.modified_count == 1 {
        client
            .database(DB_SESSIONS)
            .collection::<SessionDocument>(COL_PASSWORD_RESET)
            .delete_one(find_reset_by_uuid, None)
            .await?;
        return Ok(StatusCode::OK);
    } else {
        return Ok(StatusCode::IM_A_TEAPOT);
    }
}

async fn create_anon_account(
    State(state): State<Arc<SharedState>>,
) -> Result<impl IntoResponse, AppError> {
    let username = uuid::Uuid::new_v4().to_string();
    let pass = &username.to_string()[..8];
    let salt = SaltString::generate(&mut OsRng);
    let pass_hash = match argon2::Argon2::default().hash_password(pass.as_bytes(), &salt) {
        Ok(hash) => hash,
        Err(_) => return Err(AppError(anyhow!("anon fail"))),
    };

    state
        .mongo_client
        .database(DB_USER)
        .collection(COL_USER_CREDS)
        .insert_one(
            doc! {
                "_id": &username,
                "pass_hash": pass_hash.to_string(),
            },
            None,
        )
        .await?;
    let sess_id = mongodb::bson::Uuid::new();
    state
        .mongo_client
        .database(DB_SESSIONS)
        .collection(COL_USER_SESS)
        .insert_one(
            doc! {
                "_id": sess_id,
                "user_email": &username,
                "expiry_date": Utc::now().add(chrono::Duration::days(30)),
            },
            None,
        )
        .await?;

    // let cook = Cookie::build((COOKIE_SESSION, sess_id.to_string()))
    // .path("/")
    // .http_only(true);

    return Ok((
        setCookieHeaders(&sess_id.to_string(), &username),
        (Json(doc! {"username": username, "password": pass})),
    ));
}

pub fn build(shared_state: Arc<SharedState>) -> Router {
    Router::new()
        .route("/login", post(login_user))
        .route("/register", post(register_user))
        .route("/logout", put(logout_user))
        .route("/forgot-password", post(send_email_reset))
        .route("/reset-password", post(reset_password))
        .route("/anon-account", get(create_anon_account))
        .with_state(shared_state)
}
