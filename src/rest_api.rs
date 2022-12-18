use actix_web::{get, post, Responder, HttpResponse, web};
use serde::{Serialize, Deserialize};

use crate::database_integration::{get_password_api, set_password_api};

#[derive(Debug, Serialize, Deserialize)]
struct GetRequest {
    site: String,
    master_password: String
}

#[derive(Debug, Serialize, Deserialize)]
struct GetResponse {
    password: String
}

#[derive(Debug, Serialize, Deserialize)]
struct SetRequest {
    site: String,
    password: String,
    master_password: String
}

#[derive(Debug, Serialize, Deserialize)]
struct SetResponse {
    status: bool
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .body("hello")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .body(req_body)
}

#[post("/get")]
async fn get_password(req: web::Json<GetRequest>) -> impl Responder {
    let password = get_password_api(&req.site, &req.master_password).unwrap();

    let res = GetResponse {
        password
    };

    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .json(res)
}

#[post("/set")]
async fn set_password(req: web::Json<SetRequest>) -> impl Responder {
    let status = set_password_api(&req.site, &req.password, &req.master_password).unwrap();

    let res = SetResponse {
        status
    };

    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .json(res)
}
