use rpassword;
use rusqlite::{Connection, Error, OpenFlags, Result};

use std::env;

#[derive(Debug)]
struct Password {
    site: String,
    password: String,
}

const DATABASE: &str = "password_manager.db3";

fn check_password() -> Result<bool, Error> {
    let password = rpassword::prompt_password("Enter password: ").unwrap();

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stat = conn
        .prepare("SELECT password from password WHERE site='user' AND password=(?)")
        .expect("failed to prepare!");

    let suc = stat.exists([password])?;

    Ok(suc)
}

fn init_database() -> Result<(), Error> {
    let mut password;
    loop {
        password = rpassword::prompt_password("Enter password: ").unwrap();
        if password == rpassword::prompt_password("Repeat password: ").unwrap() {
            break;
        }
    }
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

fn add_password(arg: String) -> Result<(), Error> {
    while !check_password()? {
        println!("Incorrect password")
    }

    let arg: Vec<&str> = arg.split(":").into_iter().collect();
    let site = arg.get(0).unwrap();
    let password = arg.get(1).unwrap();

    let site = Password {
        site: site.to_string(),
        password: password.to_string(),
    };

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    conn.execute(
        "INSERT INTO password (site, password) VALUES (?1, ?2)",
        (&site.site, &site.password),
    )?;

    Ok(())
}

fn get_password(site: String) -> Result<(), Error> {
    while !check_password()? {
        println!("Incorrect password")
    }

    let conn = Connection::open_with_flags(DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    let mut stat = conn.prepare("SELECT password from password WHERE site = (?)")?;
    let mut rows = stat.query([site])?;

    while let Some(row) = rows.next()? {
        let password: String = row.get(0)?;
        println!("{password}");
    }

    Ok(())
}

fn main() -> Result<(), rusqlite::Error> {
    let args: Vec<String> = env::args().collect();

    println!("{:?}", args);

    match args[1].as_str() {
        "init" => init_database(),
        "set" => add_password(args[2].clone()),
        "get" => get_password(args[2].clone()),
        _ => {
            panic!("Incorrect arguments!");
        }
    }
    .unwrap();

    Ok(())
}
