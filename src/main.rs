#![allow(unused)]

use argon2::{Argon2, password_hash::SaltString};
use argon2::{PasswordHash, PasswordHasher, PasswordVerifier};
use axum::Extension;
use axum::body::Body;
use axum::extract::Query;
use axum::http::{Request, header};
use axum::middleware::Next;
use axum::response::Response;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, HeaderMapExt};
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::{Insertable, Queryable};
use diesel::result::Error;
use dotenvy::dotenv;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::rng;
use rand::seq::{IndexedRandom, SliceRandom};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::types::uuid;

use std::{borrow::Cow, env, net::SocketAddr, process};
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::schema::passwords;
use crate::schema::users; // Import 'users' table definition

use diesel::AsChangeset;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;

use crate::schema::passwords::dsl::*;
use crate::schema::users::dsl::*;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

pub type DbPool = deadpool::managed::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

mod schema;

#[derive(Deserialize, Serialize, Debug)]
struct PasswordEntry {
    key: String,
    value: String,
}

#[derive(Deserialize, AsChangeset)]
#[diesel(table_name = passwords)]
struct PasswordEntryUpdate {
    value: String,
}

#[derive(Clone)]
struct AppState {
    db_pool: DbPool,
    jwt_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

// enum AuthError {
//     MissingToken,
//     InvalidToken,
//     ExpiredToken,
//     UserNotFound,
//     InternalServerError,
// }

#[derive(Deserialize)]
struct GeneratePasswordRequest {
    #[serde(default = "default_password_length")]
    length: u8,
    #[serde(default)]
    include_uppercase: bool,
    #[serde(default)]
    include_numbers: bool,
    #[serde(default)]
    include_symbols: bool,
}

fn default_password_length() -> u8 {
    12
}

pub enum AppError {
    // record not found in db
    NotFound,
    // general db error
    DatabaseError(Error),
    // conn error
    PoolError(deadpool::managed::PoolError<diesel_async::pooled_connection::PoolError>),
    // auth errors
    InvalidToken,
    MissingToken,
    ExpiredToken,
    // general server error
    InternalServerError(String),
}

#[derive(Serialize)]
struct ApiError {
    error: String,
    code: u16,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "The requested resource was not found.".to_string(),
            ),
            AppError::DatabaseError(db_error) => {
                eprintln!("Database Error: {:?}", db_error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "A database error occurred.".to_string(),
                )
            }
            AppError::PoolError(pool_error) => {
                eprintln!("Connection Pool Error: {:?}", pool_error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred.".to_string(),
                )
            }
            AppError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid authentication token.".to_string(),
            ),
            AppError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Missing authentication token.".to_string(),
            ),
            AppError::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                "Authentication token has expired.".to_string(),
            ),
            AppError::InternalServerError(details) => {
                eprintln!("Internal Server Error: {}", details);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred.".to_string(),
                )
            }
        };

        // final JSON response body
        let body = Json(ApiError {
            error: error_message,
            code: status.as_u16(),
        });
        (status, body).into_response()
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(error: diesel::result::Error) -> Self {
        match error {
            diesel::result::Error::NotFound => AppError::NotFound,
            _ => AppError::DatabaseError(error),
        }
    }
}

impl From<deadpool::managed::PoolError<diesel_async::pooled_connection::PoolError>> for AppError {
    fn from(
        error: deadpool::managed::PoolError<diesel_async::pooled_connection::PoolError>,
    ) -> Self {
        AppError::PoolError(error)
    }
}

#[derive(Debug, Clone, PartialEq, Queryable, Insertable, Serialize)]
#[diesel(table_name = schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub hashed_password: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub hashed_password: &'a str,
}

#[derive(Queryable, Debug)]
#[diesel(table_name = users)]
struct DbUser {
    id: uuid::Uuid,
    username: String,
    hashed_password: String,
}

#[derive(Insertable)]
#[diesel(table_name = passwords)]
pub struct NewPassword<'a> {
    pub key: &'a str,
    pub value: &'a str,
    pub user_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Queryable, Insertable, Serialize)]
#[diesel(table_name = schema::passwords)]
pub struct Password {
    pub id: Uuid,
    pub key: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: Uuid,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);

    // Load environment variables
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    // Build the Diesel/Deadpool connection pool
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
    let pool = DbPool::builder(manager)
        .build()
        .expect("Failed to create Diesel connection pool.");

    // Create the application state
    let app_state = AppState {
        db_pool: pool,
        jwt_secret,
    };

    // NOTE: sqlx::migrate! is commented out. We will address Diesel migrations next.
    // sqlx::migrate!().run(&app_state.db_pool).await.unwrap_or_else(/* ... */);

    let app = Router::new()
        .route("/", get(hello_handler))
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/generate-password", get(generate_password_handler))
        .nest(
            "/passwords",
            Router::new()
                .route("/", post(create_password_handler))
                .route("/", get(get_all_passwords_handler))
                .route("/:key", get(get_password_handler))
                .route("/:key", delete(delete_password_handler))
                .route("/:key", put(update_password_handler))
                .layer(axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    auth_middleware,
                )),
        )
        .with_state(app_state);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn hello_handler() -> String {
    "Hello, Password Manager!".to_string()
}

#[derive(Deserialize, Debug)]
struct RegisterRequest {
    username: String,
    password: String,
}

async fn register_handler(
    State(store): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    // hash password
    let password = payload.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng); // generate new random salt
    let argon2 = Argon2::default();

    let hashed_pass = match argon2.hash_password(password, &salt) {
        // Call hash_password on the argon2 instance
        Ok(hash) => hash.to_string(),
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            return Json(ApiError {
                error: "Failed to hash password.".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    // get connection from deadpool pool
    //    all Diesel operations run on a single connection.
    let mut conn = match get_connection(&store).await {
        Ok(conn) => conn,
        Err(resp) => return resp,
    };

    let new_user = NewUser {
        username: &payload.username,
        hashed_password: &hashed_pass,
    };

    let result = diesel::insert_into(users)
        .values(&new_user)
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => (
            StatusCode::CREATED,
            format!("User '{}' registered successfully.", payload.username),
        )
            .into_response(),

        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Json(ApiError {
            error: "Username already exists".to_string(),
            code: StatusCode::CONFLICT.as_u16(),
        })
        .into_response(),

        Err(e) => {
            eprintln!("Database error during user registration: {}", e);
            Json(ApiError {
                error: "Failed to register user due to a database error.".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response()
        }
    }
}

// curl -X POST -H "Content-Type: application/json" -d '{"key": "my_app_login", "value": "supersecret"}' http://127.0.0.1:3000/passwords
async fn create_password_handler(
    State(store): State<AppState>,
    Extension(auth_user_id): Extension<Uuid>,
    Json(payload): Json<PasswordEntry>, // extract JSON request body
) -> impl IntoResponse {
    let mut conn = match get_connection(&store).await {
        Ok(conn) => conn,
        Err(resp) => return resp,
    };

    let new_pass = NewPassword {
        key: &payload.key,
        value: &payload.value,
        user_id: auth_user_id,
    };

    let result = diesel::insert_into(passwords)
        .values(new_pass)
        .execute(&mut conn)
        .await;

    match result {
        Ok(_) => (
            StatusCode::CREATED,
            format!("Password for key '{}' created successfully.", payload.key),
        )
            .into_response(),

        Err(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        )) => Json(ApiError {
            error: "Key already exists".to_string(),
            code: StatusCode::CONFLICT.as_u16(),
        })
        .into_response(),

        Err(e) => {
            eprintln!("Database error during password registration: {}", e);
            Json(ApiError {
                error: "Failed to register password due to a database error.".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response()
        }
    }
}

async fn get_all_passwords_handler(
    State(store): State<AppState>,
    Extension(auth_user_id): Extension<Uuid>,
) -> impl IntoResponse {
    let mut conn = match get_connection(&store).await {
        Ok(conn) => conn,
        Err(resp) => return resp,
    };

    let result = passwords // Start with the 'passwords' table from the schema
        .filter(user_id.eq(auth_user_id)) // Find all passwords for this user
        .load::<Password>(&mut conn) // Execute the query and load results into a Vec<Password>
        .await;

    match result {
        Ok(passwords_vec) => {
            // Success. The type of passwords_vec is Vec<Password>
            (StatusCode::OK, Json(passwords_vec)).into_response()
        }
        Err(e) => {
            eprintln!("Database error retrieving all passwords: {}", e);
            Json(ApiError {
                error: "Internal server error retrieving passwords".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response()
        }
    }
}

// curl http://127.0.0.1:3000/passwords/my_app_login
async fn get_password_handler(
    State(store): State<AppState>,
    Extension(auth_user_id): Extension<Uuid>,
    Path(some_key): Path<String>,
) -> impl IntoResponse {
    let mut conn = match get_connection(&store).await {
        Ok(conn) => conn,
        Err(resp) => return resp,
    };

    let result = passwords
        .filter(key.eq(&some_key))
        .filter(user_id.eq(auth_user_id))
        .select(value)
        .first::<String>(&mut conn)
        .await;

    match result {
        Ok(password_value) => (
            StatusCode::OK,
            format!("Found password '{}'", password_value),
        )
            .into_response(),
        Err(diesel::result::Error::NotFound) => {
            (StatusCode::NOT_FOUND, "Password not found".to_string()).into_response()
        }
        Err(e) => {
            eprintln!("Internal error: {}", e);
            Json(ApiError {
                error: "Internal server error".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response()
        }
    }
}

// curl -X DELETE http://127.0.0.1:3000/passwords/my_app_login
async fn delete_password_handler(
    State(store): State<AppState>,
    Extension(auth_user_id): Extension<Uuid>,
    Path(some_key): Path<String>,
) -> impl IntoResponse {
    let mut conn = match get_connection(&store).await {
        Ok(conn) => conn,
        Err(resp) => return resp,
    };

    let result = diesel::delete(
        passwords
            .filter(key.eq(&some_key))
            .filter(user_id.eq(auth_user_id)),
    )
    .execute(&mut conn)
    .await;

    match result {
        Ok(0) => {
            // 0 rows deleted -> password not found.
            (StatusCode::NOT_FOUND, "Password not found".to_string()).into_response()
        }
        Ok(_) => {
            // 1 (or more) rows deleted -> success.
            (
                StatusCode::OK,
                format!("Password for key '{some_key:?}' deleted."),
            )
                .into_response()
        }
        Err(e) => {
            // Handle any other database errors
            eprintln!("Internal error: {}", e);
            Json(ApiError {
                error: "Internal server error".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response()
        }
    }
}

// curl -X PUT -H "Content-Type: application/json" -d '{"value": "new_updated_secret"}' http://127.0.0.1:3000/passwords/my_app_login
async fn update_password_handler(
    State(store): State<AppState>,
    Path(some_key): Path<String>,
    Extension(auth_user_id): Extension<Uuid>,
    Json(payload): Json<PasswordEntryUpdate>,
) -> impl IntoResponse {
    let mut conn = match get_connection(&store).await {
        Ok(conn) => conn,
        Err(resp) => return resp,
    };

    let result = diesel::update(
        passwords
            .filter(key.eq(&some_key))
            .filter(user_id.eq(auth_user_id)),
    )
    .set(&payload) // Pass a reference to our AsChangeset struct
    .execute(&mut conn)
    .await;

    match result {
        Ok(0) => {
            // No rows were updated, meaning the key wasn't found for that user.
            (StatusCode::NOT_FOUND, "Password not found".to_string()).into_response()
        }
        Ok(_) => {
            // One or more rows were updated successfully.
            (
                StatusCode::OK,
                format!("Password for key '{:?}' updated.", some_key),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("Internal error: {}", e);
            Json(ApiError {
                error: "Internal server error".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response()
        }
    }
}

//POST /login
async fn login_handler(
    State(store): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // ? handles the Result from get_connection()
    let mut conn = get_connection(&store).await?;

    // build and execute query
    // ? operator handles Result from db query.
    // `From<diesel::result::Error>` implementation automatically
    // converts `Error::NotFound` to `AppError::NotFound`
    let user = users
        .filter(username.eq(&payload.username))
        .select((users::id, users::username, users::hashed_password))
        .first::<DbUser>(&mut conn)
        .await?;

    // verify password
    // For errors that don't have a `From` trait, use `.map_err()`
    // to manually convert them into an AppError before using `?`.
    let parsed_hash = PasswordHash::new(&user.hashed_password).map_err(|e| {
        AppError::InternalServerError(format!("Failed to parse password hash: {}", e))
    })?;

    let argon2 = Argon2::default();
    argon2
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::InvalidToken)?;

    // generate JWT
    let now = Utc::now();
    let expiration = (now + Duration::hours(1)).timestamp();

    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(store.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::InternalServerError(format!("Failed to generate token: {}", e)))?;

    Ok((StatusCode::OK, Json(LoginResponse { token })))
}

// NEW: Authentication Middleware
async fn auth_middleware(
    State(store): State<AppState>,
    headers: header::HeaderMap, // get all headers
    mut request: Request<Body>, // incoming request
    next: Next,                 // next middleware or handler in the chain
) -> Result<Response, AppError> {
    // extract Authorization header
    let auth_header = headers.typed_get::<Authorization<Bearer>>();

    let token = match auth_header {
        Some(Authorization(bearer)) => bearer.token().to_string(),
        None => return Err(AppError::MissingToken), // No token found
    };

    // decode and Validate JWT
    let decoding_key = DecodingKey::from_secret(&store.jwt_secret.as_bytes());
    let validation = Validation::default(); // Default validation (alg, exp etc.)

    let claims = match decode::<Claims>(&token, &decoding_key, &validation) {
        Ok(token_data) => token_data.claims,
        Err(e) => {
            eprintln!("JWT decoding error: {}", e); // Log the specific error for debugging
            return match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(AppError::ExpiredToken),
                _ => Err(AppError::InvalidToken), // Catch all other JWT errors as invalid
            };
        }
    };

    // extract User ID from claims and store in request extensions
    let some_user_id = match Uuid::parse_str(&claims.sub) {
        Ok(some_id) => some_id,
        Err(e) => {
            eprintln!("Invalid UUID in token subject: {}", e);
            return Err(AppError::InvalidToken); // Malformed user ID in token
        }
    };
    request.extensions_mut().insert(some_user_id); // Store the Uuid directly

    // 4. Proceed to the next handler/middleware
    Ok(next.run(request).await)
}

// curl "http://127.0.0.1:3000/generate-password?length=24&include_uppercase=true&include_numbers=true&include_symbols=true"
async fn generate_password_handler(
    Query(params): Query<GeneratePasswordRequest>,
) -> impl IntoResponse {
    let mut rng = rng();
    let mut password_chars = Vec::new();

    let lowercase_chars: Vec<char> = ('a'..='z').collect();
    let uppercase_chars: Vec<char> = ('A'..='Z').collect();
    let number_chars: Vec<char> = ('0'..='9').collect();
    let symbol_chars: Vec<char> = "!@#$%^&*()_+-=[]{}|;:,.<>?".chars().collect();

    let mut char_set: Vec<char> = lowercase_chars.clone(); // always include lowercase

    // Ensure at least one of each requested type, and add to the general pool
    if params.include_uppercase {
        char_set.extend(&uppercase_chars);
        password_chars.push(*uppercase_chars.choose(&mut rng).unwrap()); // Ensure at least one
    }
    if params.include_numbers {
        char_set.extend(&number_chars);
        password_chars.push(*number_chars.choose(&mut rng).unwrap());
    }
    if params.include_symbols {
        char_set.extend(&symbol_chars);
        password_chars.push(*symbol_chars.choose(&mut rng).unwrap());
    }

    if char_set.is_empty() {
        // Fallback if no specific sets are chosen (shouldn't happen with default lowercase)
        char_set.extend(lowercase_chars);
    }

    // Fill the rest of the password length
    let remaining_length = params.length.saturating_sub(password_chars.len() as u8); // Avoid underflow
    for _ in 0..remaining_length {
        password_chars.push(*char_set.choose(&mut rng).unwrap());
    }

    password_chars.shuffle(&mut rng); // Shuffle to randomize order

    let generated_password: String = password_chars.iter().collect();

    (
        StatusCode::OK,
        Json(json!({"password": generated_password})),
    )
        .into_response()
}

async fn get_connection(
    store: &AppState,
) -> Result<deadpool::managed::Object<AsyncDieselConnectionManager<AsyncPgConnection>>, AppError> {
    // implemented From, so we can use ? operator for succint error handling
    Ok(store.db_pool.get().await?)
}
