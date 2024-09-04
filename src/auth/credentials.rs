use std::str::FromStr;

use actix_session::Session;
use actix_web::{http::StatusCode, web, HttpResponse, HttpResponseBuilder, Responder};
use uuid::Uuid;

use crate::{database::handler::DatabaseHandler, models::{database_models::User, server_models::MessageBody}};

use super::{hasher::Hasher, sessions::SessionManager};

///Handler that verifies credentials.
///Creates a new session and sends cookie to client side.
pub async fn verify_credentials(request: Session, body: web::Json<MessageBody>) -> impl Responder {
    match DatabaseHandler::new(){
        Ok(database_handler) => {
            let username = &body.data.username;
            let password = &body.data.password;

            let hasher = Hasher::new();
            let hashed_username = hasher.hash_username(&username);

            let mut matching_user: Vec<User> = vec![];

            //users that have matching username
            match database_handler.get_users(&hashed_username){
                Ok(users_total) => {
                    //for each user retrieve password and salt
                    users_total.iter().for_each(|user| {
                        let user_password = user.get_password();
                        let user_salt = user.get_salt();

                        //compute password given with salt found from db
                        let computed_password = hasher.hash_password(password, &user_salt);

                        //password computed and password provided match
                        if computed_password.is_ok_and(|passwd| passwd.eq(user_password)){
                            matching_user.push(user.clone())
                        }
                    });
                },
                Err(error) => {
                    println!("Error while fetching users: {:?}", error);
                    return HttpResponse::InternalServerError()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .json("Status : Database error. No such user.")
                },
            };

            match matching_user.len(){
                1 => {
                    let user = matching_user.pop().unwrap();
                    let manager = SessionManager::new();

                    match request.get::<String>("value"){
                        Ok(value) => {
                            match value{
                                Some(session_value) => {
                                    let session_name = request.get::<String>("name").unwrap();
                                    println!("Session name: {:?}", session_name);
                                    println!("Session value: {:?}", session_value);
                                    
                                    //check if session value (user id) matched user id from database
                                    if !user.get_id().eq(&Uuid::from_str(session_value.as_str()).unwrap()){
                                        let response = HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                                        .json("Status : Error during session validation.");

                                        return response
                                    }

                                    let db_session = database_handler.get_session_from_id(&Uuid::from_str(session_name.unwrap().as_str()).unwrap());
                                    println!("Found session in database: {:?}", db_session)
                                },
                                None => {
                                    let name_ins_status = request.insert("name", Uuid::new_v4().to_string());
                                    let val_ins_status = request.insert("value", user.get_id().to_string());
    
                                    if !name_ins_status.is_ok() && !val_ins_status.is_ok(){
                                        let response = HttpResponseBuilder::new(StatusCode::INTERNAL_SERVER_ERROR)
                                        .json("Status : Error during session creation.");
                                        
                                        return response
                                    }

                                    //Save session to database
                                    let res = database_handler.insert_session(&manager.create_session(user.get_id()));

                                    println!("Inserted session: {:?}", res);
                                },
                            }
                        },
                        Err(error) => {
                            println!("Error: {:?}", error)
                        },
                    }
                    let response = HttpResponseBuilder::new(StatusCode::ACCEPTED)
                    .json("Status : User validated.");

                    return response
                },
                _ => {
                    println!("Less or more than one users matched.");
                    return HttpResponse::InternalServerError()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .json("Status : Database error.")
                }
            }
            
        },
        Err(error) => {
            //HTTP ERROR response
            println!("Error while fetching database: {:?}", error);
            return HttpResponse::InternalServerError()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .json("Status : Database error. Initialization failed.")
        }
    }
}


///Handler that saves credentials to database.
pub async fn save_credentials(credentials: web::Json<MessageBody>) -> impl Responder {
    let username = &credentials.data.username;
    let password = &credentials.data.password;

    if sanitize(password){
        match DatabaseHandler::new(){
            Ok(database_handler) => {
                let mut hasher = Hasher::new();
                let salt = hasher.generate_salt_argon2(username, password);
                let hashed_username = hasher.hash_username(&username);
                let hashed_password = hasher.hash_password(password, &salt);
    
                //push to db
                match hashed_password{
                    Ok(hash) => {
                        //db push new user
                        let user = User::new(Uuid::new_v4(), hashed_username, hash, 0, salt);
                        match database_handler.insert_user(user){
                            Ok(rows) => {
                                //redirect to login
                                println!("User {:?}", rows);
                                return HttpResponse::Created()
                                .status(StatusCode::CREATED)
                                .json("Status : User created.")
                            },
                            Err(error) => {
                                println!("Error while inserting user to database: {:?}", error);
                                return HttpResponse::InternalServerError()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .json("Status : Database error.")
                            },
                        }
                    },
                    Err(error) => {
                        println!("Error while hashing password: {:?}", error);
                        return HttpResponse::InternalServerError()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .json("Status : Hasher error.")
                    },
                }
            },
            Err(error) => {
                //HTTP ERROR response
                println!("Error while opening database: {:?}", error);
                return HttpResponse::InternalServerError()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .json("Status : Database error. Connection dropped.")
            },
        }
    }

    return HttpResponse::BadRequest()
    .status(StatusCode::BAD_REQUEST)
    .json("Status : Invalid password.")
}


///Basic function to see if one of each key type is present.
///Client side sanitization is also implemented.
pub fn sanitize(password: &String) -> bool{
    let mut has_length = false;
    let mut has_digit = false;
    let mut has_letter = false;
    let mut has_special_char = false;

    password.chars().for_each(|c| {
        if c.is_ascii_digit(){
            has_digit = true;
        }
        
        if c.is_alphabetic(){
            has_letter = true;
        }

        if c.is_ascii_punctuation(){
            has_special_char = true;
        }
    });

    if password.len() >= 8{
        has_length = true;
    }
    
    return has_length && has_digit && has_letter && has_special_char
}