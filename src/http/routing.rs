use super::request::Request;

pub struct Router {

}

struct Route {
    path: String,
    callback: fn(Request)
}