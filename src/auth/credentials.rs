use actix_web::{cookie::Cookie, http::StatusCode, web, HttpResponse, HttpResponseBuilder, Responder};
use uuid::Uuid;

use crate::{database::handler::DatabaseHandler, models::{database_models::User, server_models::MessageBody}};

use super::hasher::Hasher;

pub async fn verify_credentials(credentials: web::Json<MessageBody>) -> impl Responder {
    match DatabaseHandler::new(){
        Ok(database_handler) => {
            let username = &credentials.content.username;
            let password = &credentials.content.password;

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
                //Review: Make better response
                Err(error) => {
                    //HTTP ERROR response
                    println!("{:?}", error);
                    return HttpResponse::InternalServerError()
                    .body("Error while fetching users from database.")
                },
            };

            //Review: what if more than one user match ?
            match matching_user.len(){
                0 => {
                    return HttpResponse::InternalServerError()
                    .body("Error no users matched.")
                },
                1 => {
                    //FIXME : Only proceed if one user is found
                },
                _ => {
                    return HttpResponse::InternalServerError()
                    .body("Error too many users matched.")
                }
            }

            //Review: Make better response
            //create and send cookie
            //FIXME: Add cookie to db
            return HttpResponseBuilder::new(StatusCode::ACCEPTED)
            .cookie({
                Cookie::build(username, Uuid::new_v4().to_string())
                    .secure(true)
                    .http_only(true)
                    .finish()
            })
            .finish()
            
        },
        //Review: Make better response
        Err(error) => {
            //HTTP ERROR response
            println!("{:?}", error);
            return HttpResponse::InternalServerError()
            .body("Error while fetching database instance.")
        }
    }
}


pub async fn save_credentials(credentials: web::Json<MessageBody>) -> impl Responder {
    let username = &credentials.content.username;
    let password = &credentials.content.password;

    if sanitize(password){
        match DatabaseHandler::new(){
            Ok(database_handler) => {
                let mut hasher = Hasher::new();
                let salt = hasher.generate_salt_argon2(username, password);
                let hashed_username = hasher.hash_username(&credentials.content.username);
                let hashed_password = hasher.hash_password(password, &salt);
    
                //push to db
                match hashed_password{
                    Ok(hash) => {
                        println!("Hashed username {:?}", username);
                        println!("Hashed passwd {:?}", hash);
                        //db push new user
                        let user = User::new(Uuid::new_v4(), hashed_username, hash, None, 0, salt);
                        match database_handler.insert_user(user){
                            //Review: Make better response
                            Ok(rows) => {
                                //redirect to login
                                println!("{:?}", rows);
                                return HttpResponse::Created()
                                .status(StatusCode::CREATED)
                                .body("Account created.")
                            },
                            Err(error) => {
                                println!("Error while inserting user to database: {:?}", error);
                                return HttpResponse::InternalServerError()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body("Error while appending user to database.")
                            },
                        }
                    },
                    //Review: Make better response
                    Err(error) => {
                        println!("Error while hashing password: {:?}", error);
                        return HttpResponse::InternalServerError()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Error while hashing users password.")
                    },
                }
            },
            //Review: Make better response
            Err(error) => {
                //HTTP ERROR response
                println!("Error while opening database: {:?}", error);
                return HttpResponse::InternalServerError()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Error while fetching database instance.")
            },
        }
    }

    return HttpResponse::BadRequest()
    .status(StatusCode::BAD_REQUEST)
    .body("Password doesn't fulfill sanitazation rules. Password must contain at least 8 characters.
    One digit, one letter and one special character.")
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