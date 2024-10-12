use actix_session::{config::{BrowserSession, CookieContentSecurity}, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, guard, middleware::Logger, web, App, HttpServer};

use auth::credentials::guest_credentials;
use database::handler::DatabaseHandler;
use maintenance::maintainer::Maintainer;

use crate::auth::credentials::{verify_credentials, save_credentials};
use crate::maintenance::maintainer::my_task;

mod database;
mod models;
mod auth;
mod maintenance;


#[actix_web::main]
async fn main() -> std::io::Result<()>{
    let maintainer = Maintainer::new().await;
    let res = maintainer.schedule_task(|| my_task("Midnight task")).await;
    
    if res.is_ok(){
        println!("Initialized maintainer...");
        let scheduler_handle = tokio::spawn(async move {
            maintainer.start().await;
        });
    }

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

    println!("Starting server...");
    
    HttpServer::new(||{
        App::new()
            .wrap(Logger::default())
            .wrap(cookie_handler())
            .service(
                web::resource("/verify").route(
                web::route()
                    .guard(guard::Post())
                    .to(verify_credentials)
                )
            )
            .service(
                web::resource("/sanitize").route(
                    web::route()
                        .guard(guard::Post())
                        .to(save_credentials)    
                )
            )
            .service(
                web::resource("/guest").route(
                    web::route()
                        .guard(guard::Post())
                        .to(guest_credentials)
                )
            )
    })
    .bind("127.0.0.1:8081")?
    .run()
    .await
}

//Cookie dispatcher
pub fn cookie_handler() -> SessionMiddleware<CookieSessionStore> {
    SessionMiddleware::builder(
	    CookieSessionStore::default(), Key::from(&[0; 64])
    )
    .cookie_name(String::from("almc-tech"))
    .cookie_secure(true)
    .cookie_http_only(true)
    .cookie_same_site(actix_web::cookie::SameSite::Strict)
    .cookie_content_security(CookieContentSecurity::Private)
    .session_lifecycle(BrowserSession::default())
	.build()
}
