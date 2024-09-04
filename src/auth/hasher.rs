use argon2::{password_hash::{Error, SaltString}, Argon2, PasswordHasher};
use rand::Rng;
use sha2::{Digest, Sha256};

const ARRAY_SIZE: usize = 16;
const HALF_SIZE: usize = 8;
///Object that implements the hashing functions. Sha256 and argon2 are generally used.
pub struct Hasher{}
impl Hasher{
    
    ///New hasher instance.
    pub fn new() -> Hasher{
        Hasher {}
    }

    ///Salt generation from argon2.
    pub fn generate_salt_argon2(&mut self, username: &String, password: &String) -> SaltString{
        let random_bytes: [u8;ARRAY_SIZE] = rand::thread_rng().r#gen();
        let credentials = format!("{}{}{}", username, password, hex::encode(random_bytes));
        match SaltString::encode_b64(credentials.as_bytes()){
            Ok(result) => {
                return result
            },
            //If encoding fails, retry with half the size
            Err(error) => {
                println!("Encoding failed: {:?}\nAttempting with half size...", error);
                let halved_random_bytes: [u8;HALF_SIZE] = rand::thread_rng().r#gen();
                let new_credentials = format!("{}{}{}", username, password, hex::encode(halved_random_bytes));
                return SaltString::encode_b64(new_credentials.as_bytes()).unwrap()
            },
        }
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