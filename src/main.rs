use actix_session::{config::{BrowserSession, CookieContentSecurity}, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, middleware::Logger, web, App, HttpServer};
use database::handler::DatabaseHandler;

mod database;
mod models;
mod auth;

use crate::auth::credentials::{verify_credentials, save_credentials};


#[actix_web::main]
async fn main() -> std::io::Result<()>{
    println!("Starting server...");
    let handler = DatabaseHandler::new();

    if handler.is_ok(){
        match handler.unwrap().initialize_tables(){
            Ok(_) => {
                println!("Initialized database...")
            },
            Err(error) => {
                println!("{:?}", error);
            },
        }
        
    }

    HttpServer::new(||{
        App::new()
            .wrap(Logger::default())
            .wrap(cookie_handler())
            .route("/verify", web::post().to(verify_credentials))
            .route("/sanitize", web::post().to(save_credentials))
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}

//https://webbureaucrat.gitlab.io/articles/setting-and-reading-session-cookies-in-rust-with-actix-web/
//https://chatgpt.com/share/6fadc69e-c491-4431-b64d-8bf8ade37cc5
//session handling
pub fn cookie_handler() -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(
	    CookieSessionStore::default(), Key::from(&[0; 64])
    )
    .cookie_name(String::from("some name"))
    .cookie_secure(true)
    .cookie_http_only(true)
    .cookie_same_site(actix_web::cookie::SameSite::Strict)
    .cookie_content_security(CookieContentSecurity::Private)
    .session_lifecycle(BrowserSession::default())
	.build()
}