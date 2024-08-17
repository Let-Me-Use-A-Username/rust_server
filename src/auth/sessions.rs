use actix_web::cookie::time::OffsetDateTime;
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
    
    ///Validate a session.
    pub fn validate_session(&self, session: Session, handler: DatabaseHandler){
        let now = OffsetDateTime::now_utc().unix_timestamp();

        let session = handler.get_session(session.get_id());

        //if session.expires > now { OK } else { expired }
    }

    ///Delete all sessions older than an hour.
    pub fn delete_session(&self, last_activity: i64) -> bool{
        let now = OffsetDateTime::now_utc().unix_timestamp();
        const SESSION_TIMEOUT: i64 = 60 * 60;
        
        return now - last_activity > SESSION_TIMEOUT
    }
}
