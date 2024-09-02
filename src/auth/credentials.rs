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
                0 => {
                    println!("Error no users matched");
                    return HttpResponse::InternalServerError()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .json("Status : Database error. User credentials don't match.")
                },
                1 => {
                    let user = matching_user.pop().unwrap();
                    let mut manager = SessionManager::new();

                    let user_session: Session;

                    match request.get::<String>("value"){
                        Ok(value) => {
                            if value.is_some(){
                                println!("Session value: {:?}", value.unwrap())
                            }
                            else{
                                request.insert("name", Uuid::new_v4().to_string());
                                request.insert("value", user.get_id().to_string());
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
                    println!("Error too many users matched");
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