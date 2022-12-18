use actix_cors::Cors;
use actix_web::{App, HttpServer, http};

mod database_integration;
use crate::database_integration::{init_database, add_password, get_password};

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
                .service(rest_api::hello)
                .service(rest_api::get_password)
                .service(rest_api::set_password)
                .service(rest_api::echo)
        })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
    }
    else {
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
}
