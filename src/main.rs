use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

#[derive(Deserialize, Serialize, Debug)]
struct PasswordEntry {
    key: String,
    value: String,
}

type AppStore = Arc<Mutex<HashMap<String, String>>>;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);

    // Initialize our shared, mutable application state
    let store: AppStore = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/", get(hello_handler))
        .route("/register", post(register_handler))
        // Add the new /passwords route for POST
        .route("/passwords", post(create_password_handler))
        // GET password
        .route("/passwords/:key", get(get_password_handler))
        .route("/passwords/:key", delete(delete_password_handler))
        // Pass the shared state to the router
        .with_state(store);

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
    // Handlers can return anything that implements IntoResponse
    // Acquire a lock on the mutex to safely access the HashMap
    let mut map = store.lock().unwrap();

    // Check if the key already exists (optional, but good practice for "create")
    if map.contains_key(&payload.key) {
        return (StatusCode::CONFLICT, "Key already exists".to_string()).into_response();
    }

    // Insert the new key-value pair
    map.insert(payload.key.clone(), payload.value.clone()); // Clone to move into map

    // Return a 201 Created status code with the key that was created
    (
        StatusCode::CREATED,
        format!("Password for key '{}' created successfully.", payload.key),
    )
        .into_response()
}

async fn get_password_handler(
    State(store): State<AppStore>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    // acquire lock: get a lock on your store
    let map = store.try_lock().unwrap();
    // get from HashMap
    match map.get(&key) {
        Some(pass) => (
            StatusCode::FOUND,
            format!("Found password '{}'", pass),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, format!("Password not found")).into_response(),
    }
}

async fn delete_password_handler(
    State(store): State<AppStore>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    // Acquire Lock: Get a lock on your store's Mutex.
    let mut map = store.try_lock().unwrap();
    // Remove from HashMap: Use map.remove(&key). This returns an Option<String> (the removed value if found).
    match map.remove(&key) {
        Some(removed_val) => (
            StatusCode::OK,
            format!("Password {removed_val} for key '{key}' deleted."),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Password not found".to_string()).into_response(),
    }
}
