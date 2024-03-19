use warp::Filter;
use crate::{Request, Id, json, Path, File, Read};

pub fn json_body() -> impl Filter<Extract = (Request,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 1024 * 50/*mb*/).and(warp::body::json())
}

pub fn delete_json() -> impl Filter<Extract = (Id,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 1024 * 50/*mb*/).and(warp::body::json())
}

