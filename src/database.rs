extern crate rpassword;

use rusqlite::{Connection, OpenFlags, Result};
use serde::{Serialize, Deserialize};
use rand::{rngs::OsRng, Rng};

use std::fs;

use spectrum::cryptography::{encrypt, decrypt, hash, aes::AES, sha::SHA};

#[derive(Debug)]
pub enum Error {
    Database(rusqlite::Error),
    IncorrectPassword,
    File(std::io::Error)
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::File(error)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Site {
    pub site: String,
    pub username: String,
    pub password: String,
}

const DATABASE: &str = "password_manager.db3";

fn check_password(password: &str) -> Result<AES, Error> {
    let sha = SHA::new();
    let password = hash(&sha, password.to_string());

    let crypto = AES::from_hex(&password).expect("failed to create AES struct from password");
    let password = encrypt(&crypto, password);

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stat = conn
        .prepare("SELECT password FROM password WHERE site='user' AND password=(?)")
        .expect("failed to prepare SQL statement!");

    if stat.exists([password])? {
        Ok(crypto)
    }
    else {
        Err(Error::IncorrectPassword)
    }
}

fn select_from_database(crypto: &AES, site: &str) -> Result<Site, Error> {
    let site_plain = site;
    let site = encrypt(crypto, site.to_string());

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stmt = conn.prepare("SELECT username, password FROM password WHERE site = (?)")?;

    let mut passwords = stmt.query_map([&site], |row| {
        let username: String = decrypt(crypto, row.get(0).unwrap()).unwrap();
        let password: String = decrypt(crypto, row.get(1).unwrap()).unwrap();

        Ok(Site {
            site: site_plain.to_string(),
            username,
            password
        })
    })?;

    Ok(passwords.next().unwrap().unwrap())
}

fn insert_into_database(crypto: &AES, site: &str, username: &str, password: &str) -> Result<(), Error> {
    let site = encrypt(crypto, site.to_string());
    let username = encrypt(crypto, username.to_string());
    let password = encrypt(crypto, password.to_string());

    let mut conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    let tx = conn.transaction()?;

    let result = tx.execute(
        "INSERT INTO password (site, username, password) VALUES (?1, ?2, ?3)",
        (&site, &username, &password),
    );

    if matches!(result, Err(_)) {
        tx.execute(
            "UPDATE password SET password = (?1), password = (?2) WHERE site = (?3)",
            (&username, &password, &site)
        )?;
    }

    tx.commit()?;

    Ok(())
}

pub fn init_database() -> Result<(), rusqlite::Error> {
    let mut password;
    loop {
        password = rpassword::prompt_password("Enter password: ").expect("failed to get password");
        if password == rpassword::prompt_password("Repeat password: ").expect("failed to get password") {
            break;
        }
    }

    let sha = SHA::new();
    let password = hash(&sha, password);

    let crypto = AES::from_hex(&password).expect("failed to create AES struct from password");
    let password = encrypt(&crypto, password);

    let conn = Connection::open(DATABASE)?;

    conn.execute(
        "CREATE TABLE password(
                    site        TEXT PRIMARY KEY,
                    username    TEXT,
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

pub fn get_password(site: &str, master_password: &str) -> Result<Site, Error> {
    let crypto = check_password(master_password)?;

    let site = select_from_database(&crypto, site)?;

    Ok(site)
}

pub fn set_password(site: &str, username: &str, password: &str, master_password: &str) -> Result<String, Error> {
    let crypto = check_password(master_password)?;

    insert_into_database(&crypto, site, username, password)?;

    Ok("Success".to_string())
}

pub fn gen_password(site: &str, username: &str, master_password: &str) -> Result<String, Error> {
    let crypto = check_password(master_password)?;

    const PASSWORD_LEN: usize = 16;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%&()=?${[]}<>*'^~";

    let mut rng = OsRng;
    let password: String = (0..PASSWORD_LEN).map(|_| {
        let idx = rng.gen_range(0..CHARSET.len());
        CHARSET[idx] as char
    }).collect();

    insert_into_database(&crypto, site, username, &password)?;

    Ok("Success".to_string())
}

pub fn show_passwords(master_password: &str) -> Result<Vec<Site>, Error> {
    let crypto = check_password(master_password)?;
    
    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stmt = conn.prepare("SELECT site, username, password FROM password WHERE NOT site = 'user'")?;

    let sites_iter = stmt.query_map([], |row| {
        let site: String = decrypt(&crypto, row.get(0).unwrap()).unwrap();
        let username: String = decrypt(&crypto, row.get(1).unwrap()).unwrap();
        let password: String = decrypt(&crypto, row.get(2).unwrap()).unwrap();

        Ok(Site {
            site,
            username,
            password
        })
    })?;

    let mut sites = Vec::new();

    for site in sites_iter {
        sites.push(site.unwrap());
    }

    Ok(sites)
}

pub fn delete_password(site: &str, master_password: &str) -> Result<String, Error> {
    let crypto = check_password(master_password)?;

    let site = encrypt(&crypto, site.to_string());

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    conn.execute("DELETE FROM password WHERE site = (?)", [site])?;

    Ok("Success".to_string())
}

pub fn burn(master_password: &str) -> Result<(), Error> {
    check_password(master_password)?;
    Ok(fs::remove_file(DATABASE)?)
}
