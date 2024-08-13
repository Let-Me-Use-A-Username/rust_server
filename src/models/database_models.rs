use argon2::password_hash::SaltString;
use uuid::Uuid;


#[derive(Clone)]
pub struct User{
    //FIXME : After fixing database datatypes, fix here as well
    id: Uuid,
    username: String,
    password: String,
    cookie: i32,
    active_sessions: i32,
    salt: SaltString
}
impl User{
    pub fn new(id: Uuid, username: String, password: String, cookie: i32, active_sessions: i32, salt: SaltString) -> User{
        User { 
            id: id, 
            username: username, 
            password: password, 
            cookie: cookie, 
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

    pub fn get_cookie(&self) -> &i32{
        return &self.cookie
    }

    pub fn get_active_sessions(&self) -> &i32{
        return &self.active_sessions
    }

    pub fn get_salt(&self) -> SaltString{
        return self.salt.clone()
    }
}