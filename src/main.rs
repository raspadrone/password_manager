use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

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

#[derive(Deserialize, Serialize, Debug)]
struct PasswordEntry {
    key: String,
    value: String,
}

type AppStore = Arc<Mutex<HashMap<String, String>>>;
