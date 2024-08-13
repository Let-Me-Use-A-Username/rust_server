use actix_web::{web, App, HttpServer};

mod database;
mod models;
mod auth;

use crate::auth::credentials::{verify_credentials, save_credentials};


#[actix_web::main]
async fn main() -> std::io::Result<()>{
    println!("Starting server...");

    HttpServer::new(||{
        App::new()
            .route("/verify", web::post().to(verify_credentials))
            .route("/sanitize", web::post().to(save_credentials))
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}