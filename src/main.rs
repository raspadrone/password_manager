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

use crate::schema::users; // Import 'users' table definition
use crate::schema::passwords;

use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;

pub type DbPool = deadpool::managed::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

mod schema;

#[derive(Deserialize, Serialize, Debug)]
struct PasswordEntry {
    key: String,
    value: String,
}

#[derive(Deserialize)]
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

enum AuthError {
    MissingToken,
    InvalidToken,
    ExpiredToken,
    UserNotFound,
    InternalServerError,
}

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

#[derive(Serialize)]
struct ApiError {
    error: String,
    code: u16,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Authorization token missing".to_string(),
            ),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, "Token expired".to_string()),
            AuthError::UserNotFound => (StatusCode::UNAUTHORIZED, "User not found".to_string()),
            AuthError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };
        Json(ApiError {
            error: error_message,
            code: status.as_u16(),
        })
        .into_response()
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

#[derive(sqlx::FromRow)]
struct PasswordValue {
    value: String,
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
    let mut conn = match store.db_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            // Handle pool error
            eprintln!("Failed to get DB connection from pool: {}", e);
            return Json(ApiError {
                error: "ailed to get DB connection from pool".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    let new_user = NewUser {
        username: &payload.username,
        hashed_password: &hashed_pass,
    };

    // DSL prelude and schema specifics
    use crate::schema::users::dsl::*;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

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
    let mut conn = match store.db_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            // Handle pool error
            eprintln!("Failed to get DB connection from pool: {}", e);
            return Json(ApiError {
                error: "ailed to get DB connection from pool".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    use crate::schema::passwords::dsl::*;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

    let new_pass = NewPassword {
        key: &payload.key,
        value: &payload.value,
        user_id: auth_user_id,
    };

    let result = diesel::insert_into(passwords).values(new_pass).execute(&mut conn).await;

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
    let mut conn = match store.db_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            // Handle pool error
            eprintln!("Failed to get DB connection from pool: {}", e);
            return Json(ApiError {
                error: "ailed to get DB connection from pool".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    use crate::schema::passwords::dsl::*;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

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
    Path(key): Path<String>,
) -> impl IntoResponse {
    let result = query_as!(
        PasswordValue,
        "SELECT value FROM passwords WHERE key = $1 AND user_id = $2",
        key,
        auth_user_id
    )
    .fetch_optional(&store.db_pool)
    .await;

    match result {
        Ok(Some(r)) => (StatusCode::OK, format!("Found password '{}'", r.value)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, format!("Password not found")).into_response(),
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
    Path(key): Path<String>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "DELETE FROM passwords WHERE key = $1 AND user_id = $2",
        key,
        auth_user_id
    )
    .execute(&store.db_pool)
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                (StatusCode::OK, format!("Password for key '{key}' deleted.")).into_response()
            } else {
                (StatusCode::NOT_FOUND, "Password not found".to_string()).into_response()
            }
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

// curl -X PUT -H "Content-Type: application/json" -d '{"value": "new_updated_secret"}' http://127.0.0.1:3000/passwords/my_app_login
async fn update_password_handler(
    State(store): State<AppState>,
    Path(key): Path<String>,
    Extension(auth_user_id): Extension<Uuid>,
    Json(payload): Json<PasswordEntryUpdate>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "UPDATE passwords SET value = $1, updated_at = NOW() WHERE key = $2 AND user_id = $3",
        payload.value,
        key,
        auth_user_id
    )
    .execute(&store.db_pool)
    .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                (StatusCode::OK, format!("Password for key '{key}' updated.")).into_response()
            } else {
                (StatusCode::NOT_FOUND, "Password not found".to_string()).into_response()
            }
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
) -> impl IntoResponse {
    use crate::schema::users::dsl::*;
    use diesel::prelude::*;
    use diesel_async::RunQueryDsl;

    // get a connection from pool
    let mut conn = match store.db_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("Failed to get DB connection from pool: {}", e);
            return Json(ApiError {
                error: "Failed to get DB connection from pool".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    // build and execute query
    let result = users
        .filter(username.eq(&payload.username))
        .select((id, username, hashed_password))
        .first::<DbUser>(&mut conn)
        .await;

    // handle result
    let user = match result {
        Ok(user) => user,
        Err(diesel::result::Error::NotFound) => {
            return (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()).into_response();
        }
        Err(e) => {
            eprintln!("Database error during user retrieval: {}", e);
            return Json(ApiError {
                error: "Database error".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    // verify password
    let parsed_hash = match PasswordHash::new(&user.hashed_password) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Error parsing stored password hash: {}", e);
            return Json(ApiError {
                error: "Internal server error".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    let argon2 = Argon2::default();
    if argon2
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return Json(ApiError {
            error: "Invalid credentials".to_string(),
            code: StatusCode::UNAUTHORIZED.as_u16(),
        })
        .into_response();
    }

    // generate JWT
    let now = Utc::now();
    let expiration = (now + Duration::hours(1)).timestamp();

    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(store.jwt_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error encoding JWT: {}", e);
            return Json(ApiError {
                error: "Failed to generate token".to_string(),
                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            })
            .into_response();
        }
    };

    (StatusCode::OK, Json(LoginResponse { token })).into_response()
}

// NEW: Authentication Middleware
async fn auth_middleware(
    State(store): State<AppState>,
    headers: header::HeaderMap, // get all headers
    mut request: Request<Body>, // incoming request
    next: Next,                 // next middleware or handler in the chain
) -> Result<Response, AuthError> {
    // extract Authorization header
    let auth_header = headers.typed_get::<Authorization<Bearer>>();

    let token = match auth_header {
        Some(Authorization(bearer)) => bearer.token().to_string(),
        None => return Err(AuthError::MissingToken), // No token found
    };

    // decode and Validate JWT
    let decoding_key = DecodingKey::from_secret(&store.jwt_secret.as_bytes());
    let validation = Validation::default(); // Default validation (alg, exp etc.)

    let claims = match decode::<Claims>(&token, &decoding_key, &validation) {
        Ok(token_data) => token_data.claims,
        Err(e) => {
            eprintln!("JWT decoding error: {}", e); // Log the specific error for debugging
            return match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(AuthError::ExpiredToken),
                _ => Err(AuthError::InvalidToken), // Catch all other JWT errors as invalid
            };
        }
    };

    // extract User ID from claims and store in request extensions
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Invalid UUID in token subject: {}", e);
            return Err(AuthError::InvalidToken); // Malformed user ID in token
        }
    };
    request.extensions_mut().insert(user_id); // Store the Uuid directly

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
