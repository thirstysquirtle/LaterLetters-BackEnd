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

mod auth_paths;


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

