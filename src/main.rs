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
    options::{ClientOptions, ServerApi, ServerApiVersion, IndexOptions, CreateIndexOptions},
    Client, IndexModel,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};

///Every Document in this DB has the user's Email as the key.
static DB_USER: &str = "user_auth";
static COL_USER_CREDS: &str = "user_credentials";
static COL_USER_LETTERS: &str = "user_latterLetters";

static DB_SESSIONS: &str = "login_sessions";
static COL_USER_SESS: &str = "user_sessions";
static COL_PASSWORD_RESET : &str = "Password_tokens";
static COOKIE_SESSION: &str = "sesshawn";



#[derive(Serialize, Deserialize)]
struct SessionDocument {
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
    client.database(DB_SESSIONS).collection::<SessionDocument>(COL_PASSWORD_RESET)
        .create_index(IndexModel::builder()
            .keys(doc! {"expiry_date": 1})
            .options(IndexOptions::builder().expire_after(std::time::Duration::from_secs(5)).build())
            .build(),
        None);
    client.database(DB_SESSIONS).collection::<SessionDocument>(COL_USER_SESS)
    .create_index(IndexModel::builder()
        .keys(doc! {"expiry_date": 1})
        .options(IndexOptions::builder().expire_after(std::time::Duration::from_secs(5)).build())
        .build(),
    None);
    Ok(client)
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
    use axum_extra::extract::cookie::{CookieJar,Cookie};
    use std::{collections::HashMap, ops::Add, sync::Arc};

    use crate::{SessionDocument, AppError, COL_USER_CREDS, COL_USER_SESS, DB_USER, DB_SESSIONS, COOKIE_SESSION};
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
    struct UserDocument {
        //the id is their Email
        _id: String,
        pass_hash: String,
    }

    async fn login_user(
        State(client): State<Arc<Client>>,
        Json(user_creds): Json<UserLoginCredentials>,
    ) -> Result<impl IntoResponse, AppError> {
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
                Err(_) => return Err(AppError(anyhow::anyhow!("wut")))
            };


            match argo.verify_password(user_creds.password.as_bytes(), &hash ) {
                Ok(_) => {
                let sess_id = uuid::Uuid::new_v4();
                client
                .database(DB_SESSIONS)
                .collection(COL_USER_SESS)
                .insert_one(SessionDocument{_id: sess_id,user_email:user_creds.email,expiry_date: Utc::now().add(Days::new(30)) }, None);


                let cook = Cookie::build((COOKIE_SESSION, sess_id.to_string()))
                .domain("localhost")
                .path("/").http_only(true);
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
            .collection::<UserDocument>(COL_USER_CREDS)
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
                    UserDocument {
                        _id: user_creds.email.clone(),
                        pass_hash: password_hash,
                    },
                    None,
                )
                .await?;
            let sess_id = uuid::Uuid::new_v4();
            let sess_expiry = chrono::Utc::now().add(chrono::Days::new(30));
            client.database(DB_USER).collection(COL_USER_SESS)
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
            .path("/").http_only(true);
            Ok((StatusCode::OK, [(header::SET_COOKIE, cook.to_string())]))
        } else {
            Err(AppError(anyhow::anyhow!("wut")))
        }
    }

    
    async fn logout_user(State(client): State<Arc<Client>>, jar: CookieJar ) -> Result<impl IntoResponse, AppError> {
        if let Some(sess_id) =  jar.get(COOKIE_SESSION) {
            client.database(DB_SESSIONS).collection::<SessionDocument>(COL_USER_SESS).delete_one(doc! {"_id": sess_id.to_string()}, None).await;
            Ok((StatusCode::OK, [(header::SET_COOKIE, "".to_string())]))

        } else {
            Ok((StatusCode::IM_A_TEAPOT, [(header::SET_COOKIE, "".to_string())]))
        }
    }

    async fn send_email_reset(State(client): State<Arc<Client>>,Json(user_creds): Json<UserLoginCredentials>) -> impl IntoResponse {
        
    }
    
    pub fn build(mongodb_client: Arc<Client>) -> Router {
        Router::new()
            .route("/login", post(login_user))
            .route("/register", post(register_user))
            .route("/logout", post(logout_user))
            .route("/forgot-password", po)
            .with_state(mongodb_client)
    }

}
