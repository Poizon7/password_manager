use actix_cors::Cors;
use actix_web::{App, HttpServer, http};

mod database;
mod rest_api;

use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args[1] == "api" {
        HttpServer::new(|| {
            let cors = Cors::default()
                .allow_any_origin()
                .allowed_methods(vec!["GET", "POST"])
                .allowed_header(http::header::CONTENT_TYPE)
                .max_age(3600);

            App::new()
                .wrap(cors)
                .service(rest_api::get_password)
                .service(rest_api::set_password)
        })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
    }
    else {
        match args[1].as_str() {
            "init" => {
                database::init_database().unwrap();
            },
            "set" => {
                let mut args = args[2].split(':');
                let site = args.next().unwrap();
                let username = args.next().unwrap();
                let password = args.next().unwrap();

                let master_password = &rpassword::prompt_password("Enter password: ").unwrap();

                println!("{}", database::set_password(site, username, password, master_password).unwrap());
            },
            "get" => {
                let mut args = args[2].split(':');
                let site = args.next().unwrap();

                let master_password = &rpassword::prompt_password("Enter password: ").unwrap();

                let (username, password) = database::get_password(site, master_password).unwrap();

                println!("Username: {}", username);
                println!("Password: {}", password);
            },
            "gen" => {
                let mut args = args[2].split(':');
                let site = args.next().unwrap();
                let username = args.next().unwrap();

                let master_password = &rpassword::prompt_password("Enter password: ").unwrap();

                println!("{}", database::gen_password(site, username, master_password).unwrap());
            },
            _ => {
                panic!("Incorrect arguments!");
            }
        }

        Ok(())
    }
}
