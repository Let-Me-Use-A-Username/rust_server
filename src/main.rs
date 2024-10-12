use std::sync::{Arc, Mutex};

use actix_session::{config::{BrowserSession, CookieContentSecurity}, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, guard, middleware::Logger, web, App, HttpServer};

use auth::credentials::guest_credentials;
use database::handler::DatabaseHandler;
use maintenance::maintainer::Maintainer;

use crate::auth::credentials::{verify_credentials, save_credentials};
use crate::maintenance::maintainer::guest_cleanup;

mod database;
mod models;
mod auth;
mod maintenance;


#[actix_web::main]
async fn main() -> std::io::Result<()>{
    
    //Initialize database handler
    let handler_op = DatabaseHandler::new();

    if handler_op.is_ok(){
        let handler = Arc::new(Mutex::new(handler_op.unwrap()));

        match handler.lock().unwrap().initialize_tables(){
            Ok(_) => {
                println!("Initialized database tables...")
            },
            Err(error) => {
                panic!("Error running database. {:?}", error);
            },
        }

        let maintainer = Maintainer::new().await;
        
        let res = maintainer.schedule_task({
            move || guest_cleanup(handler.clone()) // Pass the Arc<Mutex<DatabaseHandler>> to the task
        }).await;
        
        if res.is_ok(){
            println!("Initialized maintainer...");
            tokio::spawn(async move {
                maintainer.start().await;
            });
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
