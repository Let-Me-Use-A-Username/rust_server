use serde::Deserialize;

///Message body send from client. Includes Credentials.
#[derive(Deserialize, Debug)]
pub struct MessageBody {
    pub content: Credentials
}

///Credentials model sent from client side.
#[derive(Deserialize, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String
}