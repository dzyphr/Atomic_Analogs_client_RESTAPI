use std::path::Path;
use uuid::{uuid, Uuid};
use std::fs::OpenOptions;
use serde_json::{json, Value, Map};
use warp::{http, Filter};
use std::io::BufReader;
use std::fs::File;
use std::io::prelude::*;
use warp::reply::Html;
use warp::Reply;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use subprocess::{PopenConfig, Popen, Redirection};
fn json_body() -> impl Filter<Extract = (Request,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn delete_json() -> impl Filter<Extract = (Id,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn accepted_private_api_keys() -> Vec<&'static str>
{
    return vec![
        "PASSWORD"
    ]
}

fn accepted_public_api_keys() -> Vec<&'static str>
{
    return vec![
        "123"
    ]
}


fn private_accepted_request_types() -> Vec<&'static str>
{
    return vec![
        "generateEncryptedResponse"
    ]
}

fn public_accepted_request_types() -> Vec<&'static str>
{
    return vec![
    ]
}


fn ElGamal_keypaths() -> Vec<&'static str>
{
    return vec![
        "Key0.ElGamalKey"
    ]
}

fn accountNameFromChainAndIndex(chain: String, index: usize) -> &'static str
{
    if chain == "Ergo"
    {
        let accountvec = vec![
            "responderEnv"
        ];
        return accountvec[index]
    }
    if chain == "Sepolia"
    {
        let accountvec = vec![
            "basic_framework"
        ];
        return accountvec[index]
    }
    else
    {
        return "chain not found"
    }
}

#[tokio::main]
async fn main() {
    let version =  "v0.0.1";
    let main_path  = "requests";
    let public_main_path = "publicrequests";
    let OrderTypesPath = "ordertypes";

    let storage = Storage::new();
    let storage_filter = warp::any().map(move || storage.clone());
    let bearer_private_api_key_filter = warp::header::<String>("Authorization").and_then( | auth_header: String | async move {
            if auth_header.starts_with("Bearer ")
            {
                let api_key = auth_header.trim_start_matches("Bearer ").to_string();
                if accepted_private_api_keys().contains(&api_key.as_str())
                {
                    let response = warp::reply::html("API Key Valid");
                    Ok(response)
                }
                else
                {
                    Err(warp::reject::custom(Badapikey))
                }
            }
            else
            {
                Err(warp::reject::custom(Noapikey))
            }
    });
    //add and update use the same function just differ in post and put
    let add_requests = warp::post()
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(json_body())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_update_request_map);
    let update_request = warp::put() 
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(json_body())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_update_request_map);
    let get_requests = warp::get()
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_get_request_map);
    let private_delete_request = warp::delete()
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(delete_json())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_delete_request);
    let routes = add_requests.or(get_requests).or(update_request).or(private_delete_request);
    warp::serve(routes)
        .run(([127, 0, 0, 1], 3031))
        .await;
}


async fn private_delete_request(
    id: Id,
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        storage.request_map.write().remove(&id.id);
        Ok(warp::reply::with_status(
            "Removed request from request list",
            http::StatusCode::OK,
        ))
}

async fn private_update_request_map(
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
                        http::StatusCode::CREATED,
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
async fn private_get_request_map(
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let result = storage.request_map.read();
        Ok(warp::reply::json(&*result))
}

fn rem_first_and_last(value: &str) -> &str {
    let mut chars = value.chars();
    chars.next();
    chars.next_back();
    chars.as_str()
}

fn handle_request(request: Request) -> (bool, Option<String>)
{
    let mut output = "";
    let mut status = false;
    if request.request_type == "generateEncryptedResponse" 
    {
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.responderCrossChain == None
        {
            let output = &(output.to_owned() + "responderCrossChain variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.responderLocalChain == None
        {
            let output = &(output.to_owned() + "responderLocalChain variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ElGamalKey == None
        {
            let output = &(output.to_owned() + "ElGamalKey variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ElGamalKeyPath == None
        {
            let output = &(output.to_owned() + "ElGamalKeyPath variable is required!");
            return (status, Some(output.to_string()));
        }
        let swapName = request.SwapTicketID.clone().unwrap();
        status = true;
        let responderCrossChainAccountName = accountNameFromChainAndIndex(request.responderCrossChain.clone().unwrap(), 0);
        let responderLocalChainAccountName = accountNameFromChainAndIndex(request.responderLocalChain.clone().unwrap(), 0);
        let mut pipe = Popen::create(&[
            "python3",  "-u", "main.py", "GeneralizeENC_ResponseSubroutine",
            &swapName, responderCrossChainAccountName,
            responderLocalChainAccountName.clone(), &request.ElGamalKey.clone().unwrap(), &request.ElGamalKeyPath.clone().unwrap(),
            &request.responderCrossChain.clone().unwrap(), &request.responderLocalChain.clone().unwrap()
        ], PopenConfig{
            stdout: Redirection::Pipe, ..Default::default()}).expect("err");
        let (out, err) = pipe.communicate(None).expect("err");
        if let Some(exit_status) = pipe.poll()
        {
            println!("Out: {:?}, Err: {:?}", out, err)
        }
        else
        {
            pipe.terminate().expect("err");
        }
        //TODO: test full swap sequence (up til here) through RESTAPI calls only, ideally do a
        //multifolder test (maybe even w server on remote device) to get error handling ensured
        return (status, Some("response generated".to_string()))
    }
    else
    {
        return  (status, Some("Unknown Error".to_string()));
    }
}

type RequestMap = HashMap<String, String>;

#[derive(Debug)]
struct Badapikey;
impl warp::reject::Reject for Badapikey {}

#[derive(Debug)]
struct Noapikey;
impl warp::reject::Reject for Noapikey {}

#[derive(Debug)]
struct Duplicateid;
impl warp::reject::Reject for Duplicateid {}

#[derive(Debug)]
struct Badrequesttype;
impl warp::reject::Reject for Badrequesttype {}


#[derive(Debug, Deserialize, Serialize, Clone)]
struct Id {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Request {
    id: String,
    request_type: String,
    swapName: Option<String>,
    responderLocalChain: Option<String>,
    responderCrossChain: Option<String>,
    ElGamalKey:  Option<String>,
    ElGamalKeyPath: Option<String>,
    InitiatorChain: Option<String>,
    ResponderChain: Option<String>,
    ResponderJSONPath: Option<String>,
    SwapTicketID: Option<String>
}

#[derive(Clone)]
struct Storage {
   request_map: Arc<RwLock<RequestMap>>
}

impl Storage {
    fn new() -> Self {
        Storage {
            request_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

