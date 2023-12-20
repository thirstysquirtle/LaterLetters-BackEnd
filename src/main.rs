use aws_config::{meta::region::RegionProviderChain, Region};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Router,
};
use chrono::{DateTime, Utc};
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions, ServerApi, ServerApiVersion},
    Client, IndexModel,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};

///Every Document in this DB has the user's Email as the key.
static DB_USER: &str = "user_auth";
static COL_USER_CREDS: &str = "user_credentials";
// static COL_USER_LETTERS: &str = "user_latterLetters";

static DB_SESSIONS: &str = "login_sessions";
static COL_USER_SESS: &str = "user_sessions";
static COL_PASSWORD_RESET: &str = "password_reset_tokens";
static COOKIE_SESSION: &str = "sesshawn";

#[derive(Serialize, Deserialize)]
struct SessionDocument {
    _id: mongodb::bson::Uuid,
    user_email: String,
    expiry_date: DateTime<Utc>,
}

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        println!("{}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "Bruuhhh").into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

async fn start_mongo() -> mongodb::error::Result<Client> {
    let uri = "mongodb://localhost:9999/?directConnection=true&tls=false&maxPoolSize=10";
    let mut client_options = ClientOptions::parse(uri).await?;

    let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
    client_options.server_api = Some(server_api);
    let client = Client::with_options(client_options)?;

    client
        .database("admin")
        .run_command(doc! { "ping": 1 }, None)
        .await?;
    println!("Pinged your deployment. You successfully connected to MongoDB!");
    client
        .database(DB_SESSIONS)
        .collection::<SessionDocument>(COL_PASSWORD_RESET)
        .create_index(
            IndexModel::builder()
                .keys(doc! {"expiry_date": 1})
                .options(
                    IndexOptions::builder()
                        .expire_after(std::time::Duration::from_secs(5))
                        .build(),
                )
                .build(),
            None,
        )
        .await?;
    client
        .database(DB_SESSIONS)
        .collection::<SessionDocument>(COL_USER_SESS)
        .create_index(
            IndexModel::builder()
                .keys(doc! {"expiry_date": 1})
                .options(
                    IndexOptions::builder()
                        .expire_after(std::time::Duration::from_secs(5))
                        .build(),
                )
                .build(),
            None,
        )
        .await?;
    Ok(client)
}

pub struct SharedState {
    mongo_client: Client,
    ses_client: aws_sdk_sesv2::Client,
}

#[tokio::main]
async fn main() {
    let mongo_client = start_mongo().await.expect("MongoDB connection Failed");
    let region_provider = RegionProviderChain::first_try(None)
        .or_default_provider()
        .or_else(Region::new("us-east-2"));

    let aws_config = aws_config::from_env().region(region_provider).load().await;
    let ses_client = aws_sdk_sesv2::Client::new(&aws_config);

    let shared = SharedState {
        mongo_client,
        ses_client,
    };
    let shared_state = Arc::new(shared);

    let app = Router::new().nest("/user", auth_paths::build(shared_state));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

mod auth_paths {
    use anyhow::anyhow;
    use argon2::{
        password_hash::{
            rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        },
        Argon2,
    };
    use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};
    use axum::{
        extract::State,
        http::{header, StatusCode},
        response::IntoResponse,
        routing::{post, put},
        Json, Router,
    };
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    use std::{error::Error, ops::Add, sync::Arc};
    use uuid::{fmt::Hyphenated, Uuid};

    use crate::{
        AppError, SessionDocument, SharedState, COL_PASSWORD_RESET, COL_USER_CREDS, COL_USER_SESS,
        COOKIE_SESSION, DB_SESSIONS, DB_USER,
    };
    use chrono::{Days, Utc};
    use mongodb::bson::doc;
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize)]
    struct UserLoginCredentials {
        email: String,
        password: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    struct UserDocument {
        //the id is their Email
        _id: String,
        pass_hash: String,
    }

    async fn login_user(
        State(state): State<Arc<SharedState>>,
        Json(user_creds): Json<UserLoginCredentials>,
    ) -> Result<impl IntoResponse, AppError> {
        let client = &state.mongo_client;
        // println!("{} --- {}", user_creds.email, user_creds.password);
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
                            SessionDocument {
                                _id: sess_id,
                                user_email: user_creds.email,
                                expiry_date: Utc::now().add(Days::new(30)),
                            },
                            None,
                        )
                        .await?;

                    let cook = Cookie::build((COOKIE_SESSION, sess_id.to_string()))
                        .domain("localhost")
                        .path("/")
                        .http_only(true);
                    return Ok((StatusCode::OK, [(header::SET_COOKIE, cook.to_string())]));
                }
                Err(_) => return Ok((StatusCode::UNAUTHORIZED, [(header::SET_COOKIE, "".to_string())])),
            }
        } else {
            let _ = argo.hash_password(
                "To Prevent Timing Attacks".as_bytes(),
                &SaltString::generate(&mut OsRng),
            );
            return Ok((StatusCode::UNAUTHORIZED, [(header::SET_COOKIE, "".to_string())]))
        }
    }

    async fn register_user(
        State(state): State<Arc<SharedState>>,
        Json(user_creds): Json<UserLoginCredentials>,
    ) -> Result<impl IntoResponse, AppError> {
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
                    SessionDocument {
                        _id: sess_id,
                        expiry_date: sess_expiry,
                        user_email: user_creds.email,
                    },
                    None,
                )
                .await?;
            let cook = Cookie::build((COOKIE_SESSION, sess_id.to_string()))
                .domain("localhost")
                .path("/")
                .http_only(true);
            Ok((StatusCode::OK, [(header::SET_COOKIE, cook.to_string())]))
        } else {
            Err(AppError(anyhow::anyhow!("wut")))
        }
    }

    async fn logout_user(
        State(state): State<Arc<SharedState>>,
        jar: CookieJar,
    ) -> Result<impl IntoResponse, AppError> {
        let client = &state.mongo_client;
        let cook = Cookie::build((COOKIE_SESSION, "".to_string()))
            .domain("localhost")
            .path("/")
            .http_only(true);

        if let Some(sess_id) = jar.get(COOKIE_SESSION) {
            let uuid = match uuid::Uuid::parse_str(sess_id.value()) {
                Ok(res) => res,
                Err(_) => {
                    return Ok((
                        StatusCode::IM_A_TEAPOT,
                        [(header::SET_COOKIE, "".to_string())],
                    ))
                }
            };

            let res = client
                .database(DB_SESSIONS)
                .collection::<SessionDocument>(COL_USER_SESS)
                .delete_one(doc! {"_id": uuid}, None)
                .await?;
            if res.deleted_count == 1 {
                return Ok((StatusCode::OK, [(header::SET_COOKIE, cook.to_string())]));
            }
        }
        Ok((
            StatusCode::IM_A_TEAPOT,
            [(header::SET_COOKIE, cook.to_string())],
        ))
    }

    async fn send_email_reset(
        State(state): State<Arc<SharedState>>,
        Json(user_creds): Json<UserLoginCredentials>,
    ) -> Result<impl IntoResponse, AppError> {
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
            Err(_) => return Ok(StatusCode::IM_A_TEAPOT)
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
            let del_sess = client.database(DB_SESSIONS).collection::<SessionDocument>(COL_PASSWORD_RESET)
                .delete_one(find_reset_by_uuid, None).await?;
            return Ok(StatusCode::OK);
        } else {
            return Ok(StatusCode::IM_A_TEAPOT);
        }
    }

    pub fn build(shared_state: Arc<SharedState>) -> Router {
        Router::new()
            .route("/login", post(login_user))
            .route("/register", post(register_user))
            .route("/logout", put(logout_user))
            .route("/forgot-password", post(send_email_reset))
            .route("/reset-password", post(reset_password))
            .with_state(shared_state)
    }
}
