use std::{io, str::FromStr};

use argon2::password_hash::SaltString;
use rusqlite::{Connection, Error, Result};
use uuid::Uuid;

use crate::models::database_models::{Session, User};

static DATABASE_PATH:&'static str  = "./user_database.db3";

pub struct DatabaseHandler{
    connection: Connection
}
impl DatabaseHandler{
    ///Get new database handler instance.
    pub fn new() -> Result<DatabaseHandler>{
        let connection = Connection::open(DATABASE_PATH);

        if connection.is_ok(){
            return Ok(DatabaseHandler {
                connection: connection.unwrap()
            });
        }
        return Err(connection.err().unwrap());
    }
    
    ///Initialize database tables.
    pub fn initialize_tables(&self) -> Result<usize, Error>{
        let user = self.connection.execute(
            "CREATE TABLE IF NOT EXISTS user(
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                active_sessions INTEGER DEFAULT 0,
                salt TEXT NOT NULL
            );",
        (),
        );

        if user.is_err(){
            return user
        }

        let session = self.connection.execute(
            "CREATE TABLE IF NOT EXISTS session(
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES user(id),
                created INTEGER NOT NULL,
                expires INTEGER NOT NULL  
            );", 
            (),
        );

        if session.is_err(){
            return session
        }

        return Ok(user.unwrap() + session.unwrap())
    }

    ///Drop all tables for re-initialization.
    pub fn drop_tables(&self) -> Result<usize, Error>{
        let res = self.connection.execute(
            "DROP TABLE IF EXISTS user;
                DROP TABLE IF EXISTS session",
            (),
        );

        return res;
    }

    ///Query database for debugging.
    pub fn query_db(&self) {
        loop{
            let mut string_query = String::new();
            let _ = io::stdin().read_line(&mut string_query);
            let statement = self.connection.prepare(&string_query);

            match statement.unwrap().query(rusqlite::params![]){
                Ok(mut result) => {
                    loop{
                        let row = result.next().unwrap();

                        if row.is_some(){
                            println!("Row {:?}", row);
                        }
                    }
                },
                Err(error) => {
                    println!("Error {:?}", error);
                },
            }
        }
    }

    ///Get all users with matching username.
    pub fn get_users(&self, username: &String) -> Result<Vec<User>, Error>{
        let statement = self.connection.prepare("SELECT * FROM user WHERE username = ?1");

        match statement.unwrap().query(rusqlite::params![username]){
            Ok(mut rows) => {
                let mut users: Vec<User> = vec![];
                
                loop{
                    let row = rows.next().unwrap();
                    
                    match row{
                        Some(user) => {
                            let id: String = user.get_unwrap(0);
                            let username: String = user.get_unwrap(1);
                            let password: String = user.get_unwrap(2);
                            let active_sessions: i32 = user.get_unwrap(3);
                            let salt: String = user.get_unwrap(4);
                            users.push(User::new(
                                Uuid::from_str(&id).unwrap(), 
                                username, 
                                password, 
                                active_sessions, 
                                SaltString::from_b64(&salt).unwrap()
                            ))
                        },
                        None => {
                            return Ok(users);
                        },
                    }
                }
            },
            Err(error) => {
                return Err(error)
            },
        }
    }

    ///Insert new user to database.
    pub fn insert_user(&self, user: User) -> Result<usize, Error>{
        let statement = self.connection.prepare(
            "INSERT INTO user(id, username, password, active_sessions, salt)
            VALUES (?1, ?2, ?3, ?4, ?5)"
        );
        
        return statement.unwrap().execute((
            user.get_id().to_string(), 
            user.get_username(), 
            user.get_password(),
            user.get_active_sessions(), 
            user.get_salt().to_string()
        ))
    }

    ///Get session with matching id.
    pub fn get_session_from_id(&self, session_id: &Uuid) -> Result<Option<Session>, Error>{
        let statement = self.connection.prepare(
            "SELECT * FROM session WHERE session_id = ?1"
        );

        match statement.unwrap().query(rusqlite::params![session_id.to_string()]){
            Ok(mut rows) => {
                let mut sessions: Vec<Session> = vec![];

                loop{
                    let row = rows.next().unwrap();
                    
                    match row{
                        Some(session) => {
                            let session_id: String = session.get_unwrap(0);
                            let user_id: String = session.get_unwrap(1);
                            let created: i64 = session.get_unwrap(2);
                            let expires: i64 = session.get_unwrap(3);
                            sessions.push(Session::new(
                                Uuid::from_str(&session_id).unwrap(), 
                                Uuid::from_str(&user_id).unwrap(), 
                                created, 
                                expires, 
                            ))
                        },
                        None => {
                            println!("Sessions from db: {:?}", sessions);
                            if sessions.len() == 0{
                                return Ok(None)
                            }

                            return Ok(Some(sessions.pop().unwrap()));
                        },
                    }
                }
            },
            Err(error) => {
                return Err(error)
            },
        }
    }

    ///Insert new session to database.
    pub fn insert_session(&self, session: &Session) -> Result<usize, Error>{
        let statement = self.connection.prepare(
            "INSERT INTO session(session_id, user_id, created, expires) 
            VALUES (?1, ?2, ?3, ?4)"
        );

        println!("Inserted Session");

        return statement.unwrap().execute((
            session.get_id().to_string(),
            session.get_user_id().to_string(),
            session.get_created(),
            session.get_expires()
        ))
    }

    ///Updates or inserts a session.
    pub fn update_session(&self, session: &Session) -> Result<usize, Error>{
        let result = self.get_session_from_id(session.get_id());

        if result.is_ok_and(|x| x.is_some()){
            //update
            let statement = self.connection.prepare(
                "UPDATE session SET created = ?1, expires = ?2 WHERE session_id = ?3"
            );
            
            println!("Updated Session");

            return statement.unwrap().execute((
                session.get_created(), 
                session.get_expires(), 
                session.get_id().to_string()
            ))
        }

        return self.insert_session(session);
    }

}