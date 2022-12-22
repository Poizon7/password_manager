use actix_web::{post, HttpResponse, web};
use serde::{Serialize, Deserialize};

use crate::database;

#[derive(Debug, Deserialize)]
struct GetRequest {
    site: String,
    master_password: String
}

#[derive(Debug, Serialize)]
struct GetResponse {
    username: String,
    password: String
}

#[derive(Debug, Deserialize)]
struct SetRequest {
    site: String,
    username: String,
    password: String,
    master_password: String
}

#[derive(Debug, Serialize)]
struct SetResponse {
    status: String
}

#[post("/get")]
async fn get_password(req: web::Json<GetRequest>) -> HttpResponse {
    let site = database::get_password(&req.site, &req.master_password).unwrap();

    let res = GetResponse {
        username: site.username,
        password: site.password
    };

    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .json(res)
}

#[post("/set")]
async fn set_password(req: web::Json<SetRequest>) -> HttpResponse {
    let status = database::set_password(&req.site, &req.username, &req.password, &req.master_password).unwrap();

    let res = SetResponse {
        status
    };

    HttpResponse::Ok()
        .insert_header(("Content-Security-Policy", "default-src 'self' *"))
        .json(res)
}
