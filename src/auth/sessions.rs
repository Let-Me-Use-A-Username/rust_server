use uuid::Uuid;

use crate::models::database_models::Session;


pub struct SessionManager{}

impl SessionManager{
    ///Get a session manager.
    pub fn new() -> Self{
        SessionManager {}
    }

    ///Create session for a specified user id. Session time is one hour.
    pub fn create_session(&self, user_id: &Uuid) -> Session{
        let session_id = Uuid::new_v4();

        return Session::new(session_id, *user_id)
    }
    

    pub fn guest_session(&self) -> Session{
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        return Session::new(session_id, user_id)
    }
}
