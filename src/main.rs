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
                .service(rest_api::gen_password)
        })
        .bind(("127.0.0.1", 8080)).expect("failed to bind server to port")
        .run()
        .await
    }
    else {
        match args[1].as_str() {
            "init" => {
                database::init_database().expect("failed to initialise database");
            },
            "set" => {
                let mut args = args[2].split(':');
                let site = args.next().expect("incorrect arguments should be formated site:username:password");
                let username = args.next().expect("incorrect arguments should be formated site:username:password");
                let password = args.next().expect("incorrect arguments should be formated site:username:password");

                let master_password = &rpassword::prompt_password("Enter password: ").expect("failed to get password");

                println!("{}", database::set_password(site, username, password, master_password).expect("failed to set password"));
            },
            "get" => {
                let mut args = args[2].split(':');
                let site = args.next().expect("incorrect arguments should be formated site");

                let master_password = &rpassword::prompt_password("Enter password: ").expect("failed to get password");

                let site = database::get_password(site, master_password).expect("failed to get password");

                println!("Username: {}", site.username);
                println!("Password: {}", site.password);
            },
            "gen" => {
                let mut args = args[2].split(':');
                let site = args.next().expect("incorrect arguments should be formated site:username");
                let username = args.next().expect("incorrect arguments should be formated site:username");

                let master_password = &rpassword::prompt_password("Enter password: ").expect("failed to get password");

                println!("{}", database::gen_password(site, username, master_password).expect("failed to generate password"));
            },
            "show" => {
                let master_password = &rpassword::prompt_password("Enter password: ").expect("failed to get password");

                let sites = database::show_passwords(master_password).expect("failed to show password");

                for site in sites {
                    println!();
                    println!("{}", site.site);
                    println!("Username: {}", site.username);
                    println!("Password: {}", site.password);
                }
            }
            "del" => {
                let site = args[2].clone();

                let master_password = &rpassword::prompt_password("Enter password: ").expect("failed to get password");

                println!("{}", database::delete_password(&site, master_password).expect("failed to delete password"));
            }
            "burn" => {
                let master_password = &rpassword::prompt_password("Enter password: ").expect("failed to get password");

                database::burn(master_password).expect("failed to delete database");

                println!("Success");
            }
            _ => {
                panic!("Incorrect arguments!");
            }
        }

        Ok(())
    }
}
