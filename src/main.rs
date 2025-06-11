use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, query, query_as};
use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    net::SocketAddr,
    process,
    sync::{Arc, Mutex},
};
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
        // Add the new /passwords route for POST
        .route("/passwords", post(create_password_handler))
        // GET password
        .route("/passwords/:key", get(get_password_handler))
        .route("/passwords/:key", delete(delete_password_handler))
        // .route("/passwords/:key", put(update_password_handler))
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

async fn register_handler(Json(payload): Json<RegisterRequest>) -> String {
    println!("Received registration request: {:?}", payload);
    format!(
        "User '{}' registered (dummy): Password length {}",
        payload.username,
        payload.password.len()
    )
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            eprintln!("Internal error: {e}"),
        )
            .into_response(),
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            eprintln!("Internal error: {e}"),
        )
            .into_response(),
    }
}

// // curl -X PUT -H "Content-Type: application/json" -d '{"value": "new_updated_secret"}' http://127.0.0.1:3000/passwords/my_app_login
// async fn update_password_handler(
//     State(store): State<AppStore>,
//     Path(key): Path<String>,
//     Json(payload): Json<PasswordEntryUpdate>,
// ) -> impl IntoResponse {
//     let mut map = store.lock().unwrap();

//     match map.insert(key.clone(), payload.value.clone()) {
//         Some(old_val) => (
//             // if key had pass value, update
//             StatusCode::OK,
//             format!("Password {old_val} for key '{key}' updated."),
//         )
//             .into_response(),
//         None => (
//             // else create new pass value
//             StatusCode::CREATED,
//             "Password created for {key}".to_string(),
//         )
//             .into_response(),
//     }
// }
