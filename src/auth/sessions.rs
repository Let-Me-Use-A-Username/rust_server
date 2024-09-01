use std::str::FromStr;

use actix_web::cookie::time::OffsetDateTime;
use rusqlite::Error;
use uuid::Uuid;

use crate::{database::handler::DatabaseHandler, models::database_models::Session};


pub struct SessionManager{}

impl SessionManager{
    ///Get a session manager.
    pub fn new() -> Self{
        SessionManager {}
    }

    ///Create session for a specified user id. Session time is one hour.
    pub fn create_session(&self, user_id: &Uuid) -> Session{
        let session_id = Uuid::new_v4();
        let created = OffsetDateTime::now_utc().unix_timestamp();
        let expires = created + 3600;

        return Session::new(session_id, *user_id, created, expires)
    }

    ///Renew session by setting expired and created.
    pub fn renew_session(&mut self, session_id: &Uuid, user_id: &Uuid) -> Session{
        let created = OffsetDateTime::now_utc().unix_timestamp();
        let expires = created + 3600;

        return Session::new(*session_id, *user_id, created, expires)
    }
    
    ///Check whether a session has expired.
    pub fn validate_session(&self, session_id: &Uuid, handler: &DatabaseHandler) -> Result<bool, Error>{
        let now = OffsetDateTime::now_utc().unix_timestamp();

        match handler.get_session_from_id(&session_id){
            Ok(session) => {

                //OK and not expired
                if session.is_some_and(|x| x.get_expires() < &now) {
                    return Ok(false)
                }
                //Ok and expired
                return Ok(true)
            },
            //Not Ok
            Err(error) => {
                return Err(error)
            },
        }
    }

    pub fn verify_cookies(&mut self, cookies: Vec<String>, user_id: &Uuid, handler: &DatabaseHandler) -> Result<Session, Error>{
        //iterate cookies, check if cookie (session_id) exists in database
        let mut valid_session: Vec<Session> = Vec::new();

        for cookie in cookies{
            let mut parts = cookie.split("=");
            let user_id = &Uuid::from_str(parts.next().unwrap()).unwrap();
            let session_id = &Uuid::from_str(parts.next().unwrap()).unwrap();

            //fetch session from database
            match handler.get_session_from_id(session_id){
                Ok(session) => {
                    //if session belongs to current user
                    println!("Found session from id: {:?}", session);
                    if session.as_ref().is_some_and(|x| x.get_user_id().eq(user_id)){
                        valid_session.push(session.unwrap());
                        println!("Pushed to valid sessions");
                    }
                    //TODO: IF sessions found but different user. Drop session from db (might be an attack)
                },
                Err(error) => {
                    println!("Error during session fetch: {:?}", error);
                },
            }
        }
        
        //renew most recent session or create one.
        match valid_session.len(){
            //1)no cookies (so no session) 
            //2)no session for this user
            //FIXME 3)session was for different user
            0 => {
                return Ok(self.create_session(user_id))
            },
            1 => {
                let session = valid_session.pop().unwrap();

                match self.validate_session(session.get_id(), handler){
                    Ok(nexp) => {
                        match nexp{
                            //valid
                            true => {
                                return Ok(self.renew_session(session.get_id(), session.get_user_id()))
                            },
                            //expired
                            false => {
                                //drop
                                //create new session
                                return Ok(self.renew_session(session.get_id(), session.get_user_id()))
                            },
                        }
                    },
                    Err(error) => {
                        println!("Database error: {:?}", error);
                        return Err(error)
                    },
                }
            },
            _ => {
                return Err(Error::InvalidQuery)
            }
        }
    }

    ///Delete all sessions older than an hour.
    pub fn delete_expired_sessions(&self, last_activity: i64) -> bool{
        let now = OffsetDateTime::now_utc().unix_timestamp();
        const SESSION_TIMEOUT: i64 = 60 * 60;
        
        return now - last_activity > SESSION_TIMEOUT
    }
}
