use crate::{Reply, Id, public_accepted_request_types, Html, Storage, Request, handle_request, private_accepted_request_types, Badrequesttype, Duplicateid};
use warp::{http, http::Method};

pub async fn private_update_request_map(
    request: Request,
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        if storage.request_map.read().contains_key(&request.id) == false //prevent overwriting request ids
        {
            if private_accepted_request_types().contains(&request.request_type.as_str())
            {
                let (handled, output) = handle_request(request.clone());
                if handled == true
                {
                    storage.request_map.write().insert(request.id, request.request_type);
                    Ok(warp::reply::with_status(
                        format!("{:?}",  output.unwrap()),
                        http::StatusCode::OK,
                    ))
                }
                else
                {
                    match output{
                        Some(ref errorstring) =>
                            Ok(warp::reply::with_status(
                                format!("Request Denied\n {:?}", output.unwrap()),
                                http::StatusCode::METHOD_NOT_ALLOWED
                            )),
                        None =>
                            Ok(warp::reply::with_status(
                                format!("Request Denied\n"),
                                http::StatusCode::METHOD_NOT_ALLOWED
                            ))
                    }
                }
            }
            else
            {
                Err(warp::reject::custom(Badrequesttype))
            }
        }
        else
        {
            Err(warp::reject::custom(Duplicateid))
        }
}

