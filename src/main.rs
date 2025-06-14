use argon2::{Argon2, password_hash::SaltString};
use argon2::{PasswordHash, PasswordHasher, PasswordVerifier};
use axum::body::Body;
use axum::http::{header, Request};
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
use chrono::{Duration, Utc};
use dotenvy::dotenv;
use jsonwebtoken::{EncodingKey, Header, encode, DecodingKey, Validation, decode, };
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::types::uuid;
use sqlx::{PgPool, query, query_as};
use uuid::Uuid;
use std::{borrow::Cow, env, net::SocketAddr, process};
use tokio::net::TcpListener;



#[derive(Deserialize, Serialize, Debug)]
struct PasswordEntry {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct PasswordEntryUpdate {
    value: String,
}

type AppStore = PgPool;

// NEW: Hardcoded JWT Secret (replace with env var in real app)
const JWT_SECRET: &[u8] = b"your-super-secret-jwt-key-please-change-me";

// NEW: Struct to map database user row
#[derive(sqlx::FromRow, Debug)]
struct DbUser {
    id: uuid::Uuid, // Assuming UUID primary key
    username: String,
    hashed_password: String,
}

// NEW: Struct for JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // User ID or username
    exp: i64,    // Expiration time (as Unix timestamp)
}

// NEW: Login Request DTO
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

// NEW: Login Response DTO
#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

enum AuthError {
    MissingToken,
    InvalidToken,
    ExpiredToken,
    UserNotFound, // Potentially from DB lookup inside middleware (though we'll use extensions for simplicity here)
    // Add other specific errors as needed
    InternalServerError, // Catch-all for unexpected errors
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
            AuthError::UserNotFound => (StatusCode::UNAUTHORIZED, "User not found".to_string()), // If you add DB check here
            AuthError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };
        (status, Json(serde_json::json!({"error": error_message}))).into_response()
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok(); // load DATABASE_URL environment variable
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);

    // Initialize our shared, mutable application state
    // let store: AppStore = Arc::new(Mutex::new(HashMap::new()));

    // NEW: Initialize PostgreSQL connection pool
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file");
    let pool = PgPool::connect(&database_url).await.unwrap_or_else(|err| {
        eprintln!("Error connecting to database: {}", err);
        process::exit(1);
    });

    // Run pending migrations. Important for dev environment.
    sqlx::migrate!().run(&pool).await.unwrap_or_else(|err| {
        eprintln!("Error running migrations: {}", err);
        process::exit(1);
    });
    println!("Database migrations applied.");
    let app = Router::new()
        .route("/", get(hello_handler))
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        // Add the new /passwords route for POST
        .route("/passwords", post(create_password_handler))
        // GET password
        .route("/passwords/:key", get(get_password_handler))
        .route("/passwords/:key", delete(delete_password_handler))
        .route("/passwords/:key", put(update_password_handler))
        // Pass the shared state to the router
        .with_state(pool.clone());

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

// async fn register_handler(Json(payload): Json<RegisterRequest>) -> String {
//     println!("Received registration request: {:?}", payload);
//     format!(
//         "User '{}' registered (dummy): Password length {}",
//         payload.username,
//         payload.password.len()
//     )
// }

async fn register_handler(
    State(store): State<PgPool>, // Now takes PgPool
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    // 1. Hash the password
    let password = payload.password.as_bytes();
    let salt = SaltString::generate(&mut OsRng); // Generate a new random salt
    let argon2 = Argon2::default();

    let hashed_password = match argon2.hash_password(password, &salt) {
        // Call hash_password on the argon2 instance
        Ok(hash) => hash.to_string(), // Convert the PasswordHash object to a String
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to hash password.".to_string(),
            )
                .into_response();
        }
    };

    // 2. Store user in database
    let result = sqlx::query!(
        "INSERT INTO users (username, hashed_password) VALUES ($1, $2)",
        payload.username,
        hashed_password
    )
    .execute(&store)
    .await;

    match result {
        Ok(_) => (
            StatusCode::CREATED,
            format!("User '{}' registered successfully.", payload.username),
        )
            .into_response(),
        Err(e) => {
            if let Some(db_err) = e.as_database_error() {
                if db_err.code() == Some(Cow::Borrowed("23505")) {
                    // Unique violation for username
                    return (StatusCode::CONFLICT, "Username already exists".to_string())
                        .into_response();
                }
            }
            eprintln!("Database error during user registration: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to register user due to database error.".to_string(),
            )
                .into_response()
        }
    }
}

// curl -X POST -H "Content-Type: application/json" -d '{"key": "my_app_login", "value": "supersecret"}' http://127.0.0.1:3000/passwords
async fn create_password_handler(
    State(store): State<AppStore>,      // Extract the shared store
    Json(payload): Json<PasswordEntry>, // Extract the JSON request body
) -> impl IntoResponse {
    let result = query!(
        "INSERT INTO passwords (key, value) VALUES ($1, $2)",
        payload.key,
        payload.value // No need to clone, sqlx takes ownership/reference appropriately
    )
    .execute(&store) // Execute the query on the pool
    .await; // Await the async operation

    match result {
        Ok(_) => (
            StatusCode::CREATED,
            format!("Password for key '{}' created successfully.", payload.key),
        )
            .into_response(),
        Err(e) => {
            // Check for specific database errors (e.g., unique constraint violation)
            if let Some(db_err) = e.as_database_error() {
                if db_err.code() == Some(Cow::Borrowed("23505")) {
                    // '23505' is common for unique_violation
                    return (StatusCode::CONFLICT, "Key already exists".to_string())
                        .into_response();
                }
            }
            eprintln!("Database error during password creation: {}", e); // Log the error for debugging
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create password due to database error.".to_string(),
            )
                .into_response()
        }
    }
}

// curl http://127.0.0.1:3000/passwords/my_app_login
async fn get_password_handler(
    State(store): State<AppStore>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    let result = query_as!(
        PasswordValue,
        "SELECT value FROM passwords WHERE key = $1",
        key
    )
    .fetch_optional(&store)
    .await;

    match result {
        Ok(Some(r)) => (StatusCode::OK, format!("Found password '{}'", r.value)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, format!("Password not found")).into_response(),
        Err(e) => {
            eprintln!("Internal error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        }
    }
}

// curl -X DELETE http://127.0.0.1:3000/passwords/my_app_login
async fn delete_password_handler(
    State(store): State<AppStore>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    let result = sqlx::query!("DELETE FROM passwords WHERE key = $1", key)
        .execute(&store)
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        }
    }
}

// curl -X PUT -H "Content-Type: application/json" -d '{"value": "new_updated_secret"}' http://127.0.0.1:3000/passwords/my_app_login
async fn update_password_handler(
    State(store): State<AppStore>,
    Path(key): Path<String>,
    Json(payload): Json<PasswordEntryUpdate>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "UPDATE passwords SET value = $1, updated_at = NOW() WHERE key = $2",
        payload.value,
        key
    )
    .execute(&store)
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        }
    }
}

// NEW HANDLER: POST /login
async fn login_handler(
    State(store): State<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // 1. Retrieve User from DB
    let user = sqlx::query_as!(
        DbUser,
        "SELECT id, username, hashed_password FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&store)
    .await;

    let user = match user {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()).into_response();
        }
        Err(e) => {
            eprintln!("Database error during user retrieval: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
                .into_response();
        }
    };

    // 2. Verify Password
    let parsed_hash = match PasswordHash::new(&user.hashed_password) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Error parsing stored password hash: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response();
        }
    };
    let argon2 = Argon2::default(); // Ensure Argon2 is initialized here if not global

    let password_verified = match argon2.verify_password(payload.password.as_bytes(), &parsed_hash)
    {
        Ok(_) => true,
        Err(_) => false, // Verification failed
    };

    if !password_verified {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()).into_response();
    }

    // 3. Generate JWT
    let now = Utc::now();
    let expiration = (now + Duration::hours(1)).timestamp(); // Token expires in 1 hour

    let claims = Claims {
        sub: user.id.to_string(), // Use user ID as subject
        exp: expiration,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error encoding JWT: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate token".to_string(),
            )
                .into_response();
        }
    };

    (StatusCode::OK, Json(LoginResponse { token })).into_response()
}


// NEW: Authentication Middleware
async fn auth_middleware(
    // State is passed to middleware if needed (e.g., database pool)
    State(_store): State<PgPool>, // _pool if not used directly here
    headers: header::HeaderMap, // Get all headers
    mut request: Request<Body>, // The incoming request
    next: Next, // The next middleware or handler in the chain
) -> Result<Response, AuthError> {
    // 1. Extract Authorization header
    let auth_header = headers.typed_get::<Authorization<Bearer>>();

    let token = match auth_header {
        Some(Authorization(bearer)) => bearer.token().to_string(),
        None => return Err(AuthError::MissingToken), // No token found
    };

    // 2. Decode and Validate JWT
    let decoding_key = DecodingKey::from_secret(JWT_SECRET);
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

    // 3. Extract User ID from Claims and Store in Request Extensions
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