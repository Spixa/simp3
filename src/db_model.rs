/*
    Database model will be here
*/
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;

#[derive(Insertable)]
#[diesel(table_name = crate::schema::user)]
pub struct NewUser {
    pub username: String,
    pub hash: String,
}

#[allow(dead_code)]
#[derive(Debug, Queryable, QueryableByName)]
#[diesel(table_name = crate::schema::user)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub hash: String,
    pub banned: bool,
}

pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to the database: {}", database_url))
}
