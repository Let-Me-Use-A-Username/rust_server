use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct MessageBody {
    pub content: Credentials
}


#[derive(Deserialize, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String
}