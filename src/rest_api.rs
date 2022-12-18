use actix_web::{post, HttpResponse, web};
use serde::{Serialize, Deserialize};

use crate::database_integration::{get_password_api, set_password_api};

#[derive(Debug, Deserialize)]
struct GetRequest {
    site: String,
    master_password: String
}

#[derive(Debug, Serialize)]
struct GetResponse {
    password: String
}

#[derive(Debug, Deserialize)]
struct SetRequest {
    site: String,
    password: String,
    master_password: String
}

#[derive(Debug, Serialize)]
struct SetResponse {
    status: bool
}

#[post("/get")]
async fn get_password(req: web::Json<GetRequest>) -> HttpResponse {
    let password = get_password_api(&req.site, &req.master_password).unwrap();

    let res = GetResponse {
        password
    };

    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .json(res)
}

#[post("/set")]
async fn set_password(req: web::Json<SetRequest>) -> HttpResponse {
    let status = set_password_api(&req.site, &req.password, &req.master_password).unwrap();

    let res = SetResponse {
        status
    };

    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .json(res)
}
