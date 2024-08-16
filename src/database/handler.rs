use std::{io, str::FromStr};

use argon2::password_hash::SaltString;
use rusqlite::{Connection, Error, Result};
use uuid::Uuid;

use crate::models::database_models::User;

static DATABASE_PATH:&'static str  = "./user_database.db3";

pub struct DatabaseHandler{
    connection: Connection
}
impl DatabaseHandler{
    pub fn new() -> Result<DatabaseHandler>{
        let connection = Connection::open(DATABASE_PATH);

        if connection.is_ok(){
            return Ok(DatabaseHandler {
                connection: connection.unwrap()
            });
        }
        return Err(connection.err().unwrap());
    }
    

    pub fn initialize_tables(&self) -> Result<usize, Error>{
        //FIXME : Create appropriate data types in database
        let res = self.connection.execute(
            "CREATE TABLE IF NOT EXISTS user(
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                cookie TEXT,
                active_sessions INTEGER DEFAULT 0,
                salt TEXT NOT NULL
            )",
        (),
        );

        return res;
    }


    pub fn drop_tables(&self) -> Result<usize, Error>{
        let res = self.connection.execute(
            "DROP TABLE IF EXISTS user",
            (),
        );

        return res;
    }

    pub fn query_db(&self) {
        loop{
            let mut string_query = String::new();
            let mut buffer = io::stdin().read_line(&mut string_query);
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


    pub fn get_users(&self, username: &String) -> Result<Vec<User>, Error>{
        let statement = self.connection.prepare("SELECT * FROM user where username = ?1");

        if statement.is_ok(){
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
                                let cookie: Option<String> = user.get_unwrap(3);
                                let active_sessions: i32 = user.get_unwrap(4);
                                let salt: String = user.get_unwrap(5);
                                users.push(User::new(
                                    Uuid::from_str(&id).unwrap(), 
                                    username, 
                                    password, 
                                    cookie, 
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
        else{
            return Err(statement.unwrap_err())
        }
    }


    pub fn insert_user(&self, user: User) -> Result<usize, Error>{
        let statement = self.connection.prepare(
            "INSERT INTO user(id, username, password, cookie, active_session, salt)
            VALUES (?1, ?2, ?3, ?4, ?5)"
        );
        //FIXME : Uuid is send as a string
        let res = statement.unwrap().execute((
            user.get_id().to_string(), 
            user.get_username(), 
            user.get_password(), 
            user.get_cookie(), 
            user.get_active_sessions(), 
            user.get_salt().to_string()
        ));
        
        return res
    }

}