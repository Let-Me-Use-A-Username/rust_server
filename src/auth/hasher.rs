use argon2::{password_hash::{Error, SaltString}, Argon2, PasswordHasher};
use rand::Rng;
use sha2::{Digest, Sha256};

///Object that implements the hashing functions. Sha256 and argon2 are generally used.
pub struct Hasher{}
impl Hasher{
    
    ///New hasher instance.
    pub fn new() -> Hasher{
        Hasher {}
    }

    ///Salt generation from sha256.
    pub fn generate_salt_sha256(&mut self, username: &String, password: &String) -> SaltString{
        let random_bytes: [u8;16] = rand::thread_rng().r#gen();
        let credentials = format!("{}{}{}", username, password, hex::encode(random_bytes));

        let mut hasher = Sha256::new();
        hasher.update(credentials.as_bytes());
        let res = hasher.finalize();

        return SaltString::encode_b64(res.as_slice()).unwrap();
    }

    ///Salt generation from argon2.
    pub fn generate_salt_argon2(&mut self, username: &String, password: &String) -> SaltString{
        let random_bytes: [u8;16] = rand::thread_rng().r#gen();
        let credentials = format!("{}{}{}", username, password, hex::encode(random_bytes));
        return SaltString::encode_b64(credentials.as_bytes()).unwrap();
    }

    ///Function that hashed a password.
    pub fn hash_username(&self, username: &String) -> String{
        let mut hasher = Sha256::new();
        hasher.update(username.as_bytes());
        let hash: String = format!("{:X}", hasher.finalize());
        
        return hash
    }

    ///Function that hashed a password based on a salt.
    pub fn hash_password(&self, password: &String, salt: &SaltString) -> Result<String, Error>{
        let argon = Argon2::default();
        
        match argon.hash_password(password.as_bytes(), salt){
            Ok(hash) => return Ok(hash.to_string()),
            Err(error) => return Err(error),
        }
    }
}