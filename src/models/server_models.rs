use serde::Deserialize;

///Message body send from client. Includes Credentials.
#[derive(Deserialize, Debug)]
pub struct MessageBody {
    pub data: Credentials
}

///Credentials model sent from client side.
#[derive(Deserialize, Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String
}