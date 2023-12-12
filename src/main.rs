use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use mongodb::{
    bson::doc,
    options::{ClientOptions, ServerApi, ServerApiVersion},
    Client,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};

///Every Document in this DB has the user's Email as the key.
static DB_USER: &str = "user_auth";
static COL_USER_CREDS: &str = "user_credentials";
static COL_USER_LETTERS: &str = "user_latterLetters";

static DB_SESSIONS: &str = "login_sessions";
static COL_USER_SESS: &str = "user_sessions";

#[derive(Serialize, Deserialize)]
struct sessionDocument {
    _id: uuid::Uuid,
    user_email: String,
    expiry_date: DateTime<Utc>,
}

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::IM_A_TEAPOT, "Bruuhhh").into_response()
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



#[tokio::main]
async fn main() {
    let client = start_mongo().await.expect("MongoDB connection Failed");
    let client = Arc::new(client);

    let app = Router::new().nest("/user", auth_path::build(client));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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
    Ok(client)
}

mod auth_path {
    use argon2::{
        password_hash::{
            rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        },
        Argon2,
    };
    use axum::{
        extract::State,
        http::{header, StatusCode},
        response::IntoResponse,
        routing::post,
        Json, Router,
    };
    use cookie::time::convert::Day;
    use std::{collections::HashMap, ops::Add, sync::Arc};

    use crate::{sessionDocument, AppError, COL_USER_CREDS, COL_USER_SESS, DB_USER, DB_SESSIONS};
    use chrono::{Utc, Days}
    use mongodb::{
        bson::{doc},
        Client, Collection, results::CollectionType,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize)]
    struct UserLoginCredentials {
        email: String,
        password: String,
    }

    #[derive(Serialize, Deserialize)]
    struct userDocument {
        //the id is their Email
        _id: String,
        pass_hash: String,
    }

    async fn login_user(
        State(client): State<Arc<Client>>,
        Json(user_creds): Json<UserLoginCredentials>,
    ) -> Result<impl IntoResponse, AppError> {
        println!("{} --- {}", user_creds.email, user_creds.password);
        let argo = Argon2::default();
       
        let query_res = client
            .database(DB_USER)
            .collection::<userDocument>(COL_USER_CREDS)
            .find_one(doc! {"_id": &user_creds.email}, None)
            .await;
        if let Ok(Some(user_acc)) = query_res {
            let hash = match PasswordHash::new(&user_acc.pass_hash) {
                Ok(hash) => hash,
                Err(_) => return Err(AppError(anyhow::anyhow!("wut")))
            }


            match argo.verify_password(user_creds.password.as_bytes(), &hash ) {
                Ok(_) => {
                let sess_id = uuid::Uuid::new_v4();
                client
                .database(DB_SESSIONS)
                .collection(COL_USER_SESS)
                .insert_one(sessionDocument{_id: sess_id,user_email:user_creds.email,expiry_date: Utc::now().add(Days::new(30)) }, None);


                let cook = cookie::Cookie::build(("sesshawn", sess_id.to_string()))
                .domain("localhost")
                .path("/");
                return Ok((StatusCode::OK, [(header::SET_COOKIE, cook.to_string())]))
                },
                Err(_) => return  Err(AppError(anyhow::anyhow!("wut")))
            }

        } else {
            argo.hash_password("To Prevent Timing Attacks".as_bytes(), &SaltString::generate(&mut OsRng));
            return Err(AppError(anyhow::anyhow!("wut")))
        }

        
    }
    
    async fn register_user(
        State(client): State<Arc<Client>>,
        Json(user_creds): Json<UserLoginCredentials>,
    ) -> Result<impl IntoResponse, AppError> {
        let user_acc = client
            .database(DB_USER)
            .collection::<userDocument>(COL_USER_CREDS)
            .find_one(doc! {"_id" : &user_creds.email}, None)
            .await;

        if let Ok(None) = user_acc {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = match argon2 .hash_password(user_creds.password.as_bytes(), &salt) {
                Ok(hash) => hash.to_string(),
                Err(_) => return Err(AppError(anyhow::anyhow!("wut")))
            };
            client
                .database(DB_USER)
                .collection(COL_USER_CREDS)
                .insert_one(
                    userDocument {
                        _id: user_creds.email.clone(),
                        pass_hash: password_hash,
                    },
                    None,
                )
                .await?;
            let sess_id = uuid::Uuid::new_v4();
            let sess_expiry = chrono::Utc::now().add(chrono::Days::new(30));
            client
                .database(DB_USER)
                .collection(COL_USER_SESS)
                .insert_one(
                    sessionDocument {
                        _id: sess_id,
                        expiry_date: sess_expiry,
                        user_email: user_creds.email,
                    },
                    None,
                )
                .await?;
            Ok((StatusCode::OK, [(header::SET_COOKIE, sess_id.to_string())]))
        } else {
            Err(AppError(anyhow::anyhow!("wut")))
        }
    }

    pub fn build(mongodb_client: Arc<Client>) -> Router {
        Router::new()
            .route("/login", post(login_user))
            .with_state(mongodb_client)
    }

    async fn verify_creds(email: &str, password: &str) -> bool {}
}
