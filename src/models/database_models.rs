use argon2::password_hash::SaltString;
use uuid::Uuid;


///User model.
#[derive(Clone)]
pub struct User{
    //FIXME : After fixing database datatypes, fix here as well
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
    used_id: Uuid,
    created: i64,
    expires: i64
}

impl Session{
    pub fn new(session_id: Uuid, user_id: Uuid, created: i64, expires: i64) -> Self{
        Self { 
            id: session_id, 
            used_id: user_id, 
            created: created, 
            expires: expires 
        }
    }

    pub fn get_id(&self) -> &Uuid{
        return &self.id
    }

    pub fn get_user_id(&self) -> &Uuid{
        return &self.used_id
    }

    pub fn get_created(&self) -> &i64{
        return &self.created
    }

    pub fn get_expires(&self) -> &i64{
        return &self.expires
    }

    pub fn set_expires(&mut self, expires: i64) {
        self.expires = expires;
    }

    pub fn set_created(&mut self, created: i64) {
        self.created = created;
    }
}