use argon2::password_hash::SaltString;
use uuid::Uuid;


///User model.
#[derive(Clone)]
pub struct User{
    id: Uuid,
    username: String,
    password: String,
    active_sessions: i32,
    salt: SaltString
}
impl User{
    pub fn new(id: Uuid, username: String, password: String, active_sessions: i32, salt: SaltString) -> User{
        User { 
            id: id, 
            username: username, 
            password: password, 
            active_sessions: active_sessions, 
            salt: salt 
        }
    }

    pub fn get_id(&self) -> &Uuid{
        return &self.id
    }

    pub fn get_username(&self) -> &String{
        return &self.username
    }

    pub fn get_password(&self) -> &String{
        return &self.password
    }

    pub fn get_active_sessions(&self) -> &i32{
        return &self.active_sessions
    }

    pub fn get_salt(&self) -> SaltString{
        return self.salt.clone()
    }
}

#[derive(Debug)]
///Session model.
pub struct Session{
    id: Uuid,
    user_id: Uuid,
}

impl Session{
    pub fn new(session_id: Uuid, user_id: Uuid) -> Self{
        Self { 
            id: session_id, 
            user_id: user_id
        }
    }

    pub fn get_id(&self) -> &Uuid{
        return &self.id
    }

    pub fn get_user_id(&self) -> &Uuid{
        return &self.user_id
    }
}