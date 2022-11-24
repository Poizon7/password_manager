use rusqlite::{params, Connection, Result};

#[derive(Debug)]
struct Password {
    site: String,
    password: String,
}

fn main() -> Result<(), rusqlite::Error> {
    let conn = Connection::open_in_memory()?;

    conn.execute(
        "CREATE TABLE password(
            id          INTEGER PRIMARY KEY,
            site        TEXT NOT NULL,
            password    TEXT NOT NULL
        )",
        (),
    )?;

    let site = Password {
        site: "google.com".to_string(),
        password: "password".to_string(),
    };

    conn.execute(
        "INSERT INTO password (site, password) VALUES (?1, ?2)",
        (&site.site, &site.password),
    )?;

    let mut stmt = conn.prepare("SELECT site, password FROM password")?;
    let person_iter = stmt.query_map([], |row| {
        Ok(Password {
            site: row.get(0)?,
            password: row.get(1)?,
        })
    })?;

    for person in person_iter {
        println!("Found person {:?}", person.unwrap());
    }
    Ok(())
}
