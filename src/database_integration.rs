extern crate rpassword;
use rusqlite::{Connection, OpenFlags, Result};
use serde::{Serialize, Deserialize};

use spectrum::cryptography::{encrypt, decrypt, hash, aes::AES, sha::SHA};

#[derive(Debug)]
pub enum APIError {
    DatabaseError(rusqlite::Error),
    IncorrectPassword
}

impl From<rusqlite::Error> for APIError {
    fn from(error: rusqlite::Error) -> Self {
        Self::DatabaseError(error)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Password {
    pub site: String,
    pub password: String,
}

const DATABASE: &str = "password_manager.db3";

fn encrypt_password(password: String) -> (String, AES) {
    let sha = SHA::new();
    let password = hash(&sha, password);

    let crypto = AES::from_hex(&password).unwrap();
    (encrypt(&crypto, password).unwrap(), crypto)
}

fn check_password() -> Result<AES, rusqlite::Error> {
   loop {
        let password = rpassword::prompt_password("Enter password: ").unwrap();

        let (password, crypto) = encrypt_password(password);

        let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

        let mut stat = conn
            .prepare("SELECT password from password WHERE site='user' AND password=(?)")
            .expect("failed to prepare!");

        if stat.exists([password])? {
            return Ok(crypto);
        }
        else {
            println!("Incorrect password")
        }
    };
}

pub fn init_database() -> Result<(), rusqlite::Error> {
    let mut password;
    loop {
        password = rpassword::prompt_password("Enter password: ").unwrap();
        if password == rpassword::prompt_password("Repeat password: ").unwrap() {
            break;
        }
    }

    let (password, _) = encrypt_password(password);

    let conn = Connection::open(DATABASE)?;

    conn.execute(
        "CREATE TABLE password(
                    site        TEXT PRIMARY KEY,
                    password    TEXT NOT NULL
                )",
        (),
    )?;

    conn.execute(
        "INSERT INTO password (site, password) VALUES ('user', ?)",
        [password],
    )?;

    Ok(())
}

pub fn add_password(arg: String) -> Result<(), rusqlite::Error> {
    let crypto = check_password()?;

    let arg: Vec<&str> = arg.split(':').into_iter().collect();
    let site = arg.first().unwrap();
    let password = arg.get(1).unwrap();

    let site = Password {
        site: encrypt(&crypto, site.to_string()).unwrap(),
        password: encrypt(&crypto, password.to_string()).unwrap()
    };

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    conn.execute(
        "INSERT INTO password (site, password) VALUES (?1, ?2)",
        (&site.site, &site.password),
    )?;

    Ok(())
}

pub fn get_password(site: String) -> Result<(), rusqlite::Error> {
    let crypto = check_password()?;

    let site = encrypt(&crypto, site).unwrap();

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stat = conn.prepare("SELECT password from password WHERE site = (?)")?;
    let mut rows = stat.query([site])?;

    while let Some(row) = rows.next()? {
        let mut password: String = row.get(0)?;

        password = decrypt(&crypto, password).unwrap();

        println!("{password}");
    }

    Ok(())
}

fn check_password_api(password: &str) -> Result<AES, APIError> {
    let (password, crypto) = encrypt_password(password.to_string());

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stat = conn
        .prepare("SELECT password from password WHERE site='user' AND password=(?)")
        .expect("failed to prepare!");

    if stat.exists([password])? {
        Ok(crypto)
    }
    else {
        Err(APIError::IncorrectPassword)
    }
}

pub fn get_password_api(site: &str, password: &str) -> Result<String, APIError> {
    let crypto = check_password_api(password)?;

    let site = encrypt(&crypto, site.to_string()).unwrap();

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stat = conn.prepare("SELECT password from password WHERE site = (?)")?;
    let mut rows = stat.query([site])?;

    let mut password = String::from("");
    while let Some(row) = rows.next()? {
        password = row.get(0)?;

        password = decrypt(&crypto, password).unwrap();
    }

    Ok(password)
}

pub fn set_password_api(site: &str, password: &str, master_password: &str) -> Result<bool, APIError> {
    let crypto = check_password_api(master_password)?;

    let site = encrypt(&crypto, site.to_string()).unwrap();
    let password = encrypt(&crypto, password.to_string()).unwrap();

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    conn.execute(
        "INSERT INTO password (site, password) VALUES (?1, ?2)",
        (&site, &password),
    )?;

    Ok(true)
}
