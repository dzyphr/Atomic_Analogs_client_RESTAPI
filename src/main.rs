#![allow(non_snake_case)]
#![allow(unused_parens)]
extern crate serde_json;
use std::path::Path;
use warp::cors;
use std::fs;
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
use std::process::{Command, Stdio};
use std::thread;
use num_bigint::BigInt;
mod math;
use math::{big_is_prime};
use std::collections::BTreeMap;
use serde_json::from_str;
fn json_body() -> impl Filter<Extract = (Request,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 1024 * 50/*mb*/).and(warp::body::json())
}

fn delete_json() -> impl Filter<Extract = (Id,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 1024 * 50/*mb*/).and(warp::body::json())
}


fn accepted_private_api_keys() -> Vec<String>
{
    let accepted_private_api_keys_filepath = "accepted_private_api_keys.json";
    let mut file = match File::open(&accepted_private_api_keys_filepath) {
        Ok(file) => file,
        Err(_) => todo!()
    };
    let mut contents = String::new();
    if let Err(e) = file.read_to_string(&mut contents) {
        eprintln!("Error reading file: {}", e);
    }
    let json_value: Value = match serde_json::from_str(&contents) {
        Ok(value) => value,
        Err(_) => todo!()
    };
    let values: Vec<String> = json_value
        .as_object()
        .expect("JSON should be an object")
        .values()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    return values
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
        "generateEncryptedResponse",
        "makeSwapDir",
        "ENCresponderClaim",
        "loadElGamalPubs",
        "readSwapFile",
        "SigmaParticle_box_to_addr",
        "writeSwapFile",
        "ElGamal_decrypt_swapFile",
        "checkBoxValue",
        "updateMainEnv",
        "initErgoAccountNonInteractive",
        "initSepoliaAccountNonInteractive",
        "checkElGQGChannelCorrectness",
        "generateElGKeySpecificQG"
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
    if chain == "TestnetErgo"
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
    let public_main_path = "publicrequests"; //might never need this until client features include server hosting type abilities
//    let OrderTypesPath = "ordertypes";
    let ElGamalPubsPath = "ElGamalPubs";
    let ElGamalQChannelsPath = "ElGamalQGChannels";
    let QPubkeyArrayPath = "QGPubkeyArray";
    let cors = cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST"])
        .allow_headers(vec!["Content-Type", "Authorization"]);
    let storage = Storage::new();
    let storage_filter = warp::any().map(move || storage.clone());
    let bearer_private_api_key_filter = warp::header::<String>("Authorization").and_then( | auth_header: String | async move {
            if auth_header.starts_with("Bearer ")
            {
                let api_key = auth_header.trim_start_matches("Bearer ").to_string();
                if accepted_private_api_keys().contains(&api_key)
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
        .and_then(private_update_request_map)
        .with(cors.clone());
    let update_request = warp::put() 
        .and(warp::path(version))
        .and(warp::path(main_path))
        .and(warp::path::end())
        .and(json_body())
        .and(storage_filter.clone())
        .and(bearer_private_api_key_filter)
        .and_then(private_update_request_map)
        .with(cors.clone());
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
    let get_ElGamalPubs = warp::get()
        .and(warp::path(version))
        .and(warp::path(ElGamalPubsPath))
        .and(warp::path::end())
        .and_then(get_ElGamalPubs)
        .with(cors.clone());
    let get_ElGamalQChannels = warp::get()
        .and(warp::path(version))
        .and(warp::path(ElGamalQChannelsPath))
        .and(warp::path::end())
        .and_then(get_ElGamalQChannels)
        .with(cors.clone());
    let get_QPubkeyArray = warp::get()
        .and(warp::path(version))
        .and(warp::path(public_main_path))
        .and(warp::path(QPubkeyArrayPath))
        .and(warp::path::end())
        .and_then(get_QPubkeyArray);
    let routes = 
        add_requests.or(get_requests).or(update_request).or(private_delete_request)
        .or(get_ElGamalPubs).or(get_ElGamalQChannels).or(get_QPubkeyArray);
    warp::serve(routes)
        .run(([127, 0, 0, 1], 3031))
        .await;
}

async fn get_ElGamalPubs() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalPubKeys.json";
    readJSONfromfilepath(filepath).await
}

async fn get_ElGamalQChannels() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalQChannels.json";
    readJSONfromfilepath(filepath).await
}

async fn get_QPubkeyArray() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "QPubkeyArray.json";
    readJSONfromfilepath(filepath).await
}


async fn readJSONfromfilepath(filepath: &str) -> Result<impl warp::Reply, warp::Rejection>
{
    if Path::new(filepath).exists()
    {
        let mut file = File::open(filepath).expect("cant open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("cant read file");
        Ok(warp::reply::json(&json!(contents)))
    }
    else
    {
        Ok(warp::reply::json(&json!({"none": "none"})))
    }
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
        if request.swapAmount == None
        {
            let output = &(output.to_owned() + "swapAmount` variable is required!");
            return (status, Some(output.to_string()));
        }

        let swapName = request.SwapTicketID.clone().unwrap();
        status = true;
        let responderCrossChainAccountName = accountNameFromChainAndIndex(request.responderCrossChain.clone().unwrap(), 0);
        let responderLocalChainAccountName = accountNameFromChainAndIndex(request.responderLocalChain.clone().unwrap(), 0);
        let mut pipe = Popen::create(&[
            "python3",  "-u", "main.py", "GeneralizeENC_ResponseSubroutine",
            &swapName, responderCrossChainAccountName,
            responderLocalChainAccountName.clone(), &request.ElGamalKey.clone().unwrap(), 
            &request.ElGamalKeyPath.clone().unwrap(), &request.responderCrossChain.clone().unwrap(), 
            &request.responderLocalChain.clone().unwrap(), &request.swapAmount.clone().unwrap()
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
        let child_thread = thread::spawn(move|| {
                let mut child_process =
                    Command::new("python3")
                    .arg("-u")
                    .arg("main.py")
                    .arg("Responder_CheckLockTimeRefund")
                    .arg(swapName)
                    .stdout(Stdio::piped()) // Redirect stdout to /dev/null or NUL to detach from parent
                    .stderr(Stdio::piped()) // Redirect stderr to /dev/null or NUL to detach from parent
                    .spawn()
                    .expect("Failed to start subprocess");

                let mut output = String::new();
                let mut error_output = String::new();

                if let Some(ref mut stdout) = child_process.stdout
                {
                    stdout.read_to_string(&mut output).expect("Failed to read stdout");
                }
                else
                {
                    eprintln!("Failed to capture stdout.");
                }

                if let Some(ref mut stderr) = child_process.stderr
                {
                    stderr.read_to_string(&mut error_output).expect("Failed to read stderr");
                }
                else
                {
                    eprintln!("Failed to capture stderr.");
                }
/*
                let exit_status = child_process.wait().expect("Failed to wait for subprocess");
                if !exit_status.success() {
                    eprintln!("Subprocess failed with exit code: {:?}", exit_status);
                }
                eprintln!("Subprocess failed with exit code: {:?}", exit_status);
                eprintln!("Subprocess error output:\n{}", error_output);

                */
                let exit_status = child_process.wait().expect("Failed to wait for subprocess");
                if exit_status.success() {
                    println!("Subprocess output:\n{}", output);
                } else {
                    eprintln!("Subprocess failed with exit code: {:?}", exit_status);
                    eprintln!("Subprocess error output:\n{}", error_output);
                }
        });
        dbg!(request.SwapTicketID.clone().unwrap() + "/ENC_response_path.bin");
        let file_path = request.SwapTicketID.clone().unwrap() + "/ENC_response_path.bin";

        let file_contents = fs::read_to_string(file_path).expect("error reading file");

        //TODO: test full swap sequence (up til here) through RESTAPI calls only, ideally do a
        //multifolder test (maybe even w server on remote device) to get error handling ensured
        return (status, Some(file_contents.to_string()))
    }
    if request.request_type == "makeSwapDir"
    {
        status = true;
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ENCInit == None
        {
            let output = &(output.to_owned() + "ENCInit variable is required!");
            return (status, Some(output.to_string()));
        }
        match fs::create_dir(request.SwapTicketID.clone().expect("error swapticketid to string").to_string()) {
            Ok(_) => println!("Directory created successfully"),
            Err(err) => eprintln!("Error: {}", err),
        }
        let file_path = request.SwapTicketID.clone().unwrap() + "/ENC_init.bin";
        let mut file = match File::create(file_path) {
            Ok(file) => file,
            Err(_) => todo!()
        };
        let data = request.ENCInit.clone().unwrap();
        match file.write_all(data.as_bytes()) {
            Ok(_) => println!("Data written to file successfully"),
            Err(err) => eprintln!("Error: {}", err),
        }
        return (status, Some("swap directory generated".to_string()))
    }
    if request.request_type == "writeSwapFile"
    {
        status = true;
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.SwapFileName == None
        {
            let output = &(output.to_owned() + "SwapFileName variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.FileContents == None
        {
            let output = &(output.to_owned() + "FileContents variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let file_path = request.SwapTicketID.clone().unwrap() + "/" + &request.SwapFileName.clone().unwrap();
            let mut file = match File::create(file_path.clone()){ 
                Ok(file) => file,
                Err(_) => todo!()
            };
            let data = request.FileContents.clone().unwrap();
            match file.write_all(data.as_bytes()) {
                Ok(_) => println!("Data written to file successfully"),
                Err(err) => eprintln!("Error: {}", err),
            }
            return (status, Some(file_path + " File Saved"))
        }
    }
    if request.request_type == "ENCresponderClaim"
    {
        status = true;
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            /*
            let file_path = request.SwapTicketID.clone().unwrap() + "/ENC_finalization.bin";
            let mut file = match File::create(file_path) {
                Ok(file) => file,
                Err(_) => todo!()
            };
            let data = request.ENCFin.clone().unwrap();
            match file.write_all(data.as_bytes()) {
                Ok(_) => println!("Data written to file successfully"),
                Err(err) => eprintln!("Error: {}", err),
            }
            */
            let responderJSONPath = request.SwapTicketID.clone().unwrap() + "/responder.json";
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "GeneralizedENC_ResponderClaimSubroutine", &responderJSONPath
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
            return (status, Some("Claiming Swap".to_string()))
        }

    }
    if request.request_type == "readSwapFile"
    {
        status = true;
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.SwapFileName == None
        {
            let output = &(output.to_owned() + "SwapFileName variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let file_path = request.SwapTicketID.clone().unwrap() + "/" +  &request.SwapFileName.clone().unwrap();
            let file_contents = fs::read_to_string(file_path).expect("error reading file");
            return (status, Some(file_contents.to_string()))
        }
    }
    if request.request_type == "SigmaParticle_box_to_addr"
    {
        status = true;
        if request.boxID == None
        {
            let output = &(output.to_owned() + "boxID variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "SigmaParticle_box_to_addr", &request.boxID.clone().unwrap()
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
            return (status, Some(out.expect("not string").to_string()));
        }
    }
    if request.request_type == "ElGamal_decrypt_swapFile"
    {
        status = true;
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.SwapFileName == None
        {
            let output = &(output.to_owned() + "SwapFileName variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ElGamalKey == None
        {
            let output = &(output.to_owned() + "ElGamalKey  variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ElGamalKeyPath == None
        {
            let output = &(output.to_owned() + "ElGamalKeyPath  variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "ElGamal_decrypt", &(request.SwapTicketID.clone().unwrap() + "/" + 
                &request.SwapFileName.clone().unwrap()), &request.ElGamalKey.clone().unwrap() , 
                &request.ElGamalKeyPath.clone().unwrap()
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
            return (status, Some(out.expect("not string").to_string()));    
        }
        
    }
    if request.request_type == "checkBoxValue"
    {
        status = true;
        if request.SwapTicketID == None
        {
            let output = &(output.to_owned() + "SwapTicketID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.fileName == None
        {
            let output = &(output.to_owned() + "fileName variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.boxID == None
        {
            let output = &(output.to_owned() + "boxID variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "checkBoxValue", &request.boxID.clone().unwrap(), 
                &(request.SwapTicketID.clone().unwrap() + "/" + &request.fileName.clone().unwrap()), &request.SwapTicketID.clone().unwrap()
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
            return (status, Some(out.expect("not string").to_string()));
        }
    }
    if request.request_type == "updateMainEnv"
    {
        status = true;
        if request.Key == None
        {
            let output = &(output.to_owned() + "Key variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.Value == None
        {
            let output = &(output.to_owned() + "Value variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {

            let mut pipe  = Popen::create(&[
                "python3",  "-u", "main.py", "updateMainEnv", &request.Key.clone().unwrap(), &request.Value.clone().unwrap()
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
            return (status, Some(out.expect("not string").to_string()));
        }
    }
    if request.request_type == "initErgoAccountNonInteractive"
    {
        status = true;
        if request.ErgoTestnetNodeURL == None
        {
            let output = &(output.to_owned() + "ErgoTestnetNodeURL variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ErgoMnemonic == None
        {
            let output = &(output.to_owned() + "ErgoMnemonic variable is required!");
            return (status, Some(output.to_string()));

        }
        if request.ErgoMnemonicPass == None
        {
            let output = &(output.to_owned() + "ErgoMnemonicPass variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ErgoSenderEIP3Secret == None
        {
            let output = &(output.to_owned() + "ErgoSenderEIP3Secret variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ErgoSenderPubKey == None
        {
            let output = &(output.to_owned() + "ErgoSenderPubKey variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ErgoAPIURL == None
        {
            let output = &(output.to_owned() + "ErgoAPIURL variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.FullDirPath == None
        {
            let output = &(output.to_owned() + "FullDirPath variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.FullEnvPath == None
        {
            let output = &(output.to_owned() + "FullEnvPath variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let mut pipe  = Popen::create(&[
                "python3",  "-u", "main.py", "initErgoAccountNonInteractive", &request.ErgoTestnetNodeURL.clone().unwrap(), 
                &request.ErgoMnemonic.clone().unwrap(), &request.ErgoMnemonicPass.clone().unwrap(), 
                &request.ErgoSenderEIP3Secret.clone().unwrap(), &request.ErgoSenderPubKey.clone().unwrap(), 
                &request.ErgoAPIURL.clone().unwrap(), &request.FullDirPath.clone().unwrap(), &request.FullEnvPath.clone().unwrap()
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
            return (status, Some(out.expect("not string").to_string()));
        }
    }
    if request.request_type == "initSepoliaAccountNonInteractive"
    {
        status = true;
        if request.SepoliaSenderAddr == None
        {
            let output = &(output.to_owned() + "SepoliaSenderAddr variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.SepoliaPrivKey == None
        {
            let output = &(output.to_owned() + "SepoliaPrivKey variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.Sepolia == None
        {
            let output = &(output.to_owned() + "Sepolia variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.SepoliaID == None
        {
            let output = &(output.to_owned() + "SepoliaID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.SepoliaScan == None
        {
            let output = &(output.to_owned() + "SepoliaScan variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.SolidityCompilerVersion == None
        {
            let output = &(output.to_owned() + "SolidityCompilerVersion variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.FullDirPath == None
        {
            let output = &(output.to_owned() + "FullDirPath variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.FullEnvPath == None
        {
            let output = &(output.to_owned() + "FullEnvPath variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let mut pipe  = Popen::create(&[
                "python3",  "-u", "main.py", "initSepoliaAccountNonInteractive", &request.SepoliaSenderAddr.clone().unwrap(), 
                &request.SepoliaPrivKey.clone().unwrap(), &request.Sepolia.clone().unwrap(),
                &request.SepoliaID.clone().unwrap(), &request.SepoliaScan.clone().unwrap(), 
                &request.SolidityCompilerVersion.clone().unwrap(), &request.FullDirPath.clone().unwrap(),
                &request.FullEnvPath.clone().unwrap()
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
            return (status, Some(out.expect("not string").to_string()));
        }
    }
    if request.request_type == "checkElGQGChannelCorrectness"
    {
        status = true;
        if request.QGChannel == None
        {
            let output = &(output.to_owned() + "QGChannel variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let QG = request.QGChannel.clone().unwrap();
            let QGvec: Vec<_> = QG.split(",").collect();
            let Q = &QGvec.clone()[0];
            let G = &QGvec.clone()[1];
            //TODO CHECK G AS WELL
            let Qprime = big_is_prime(
                &Q.parse::<BigInt>().expect("error unwrapping specified q value into u64")
            );

            return (status, Some(Qprime.to_string()));
            //adding big_is_prime directly to avoid redirection waste
        }
    }
    if request.request_type == "generateElGKeySpecificQG"
    {
        status = true;
        if request.QGChannel == None
        {
            let output = &(output.to_owned() + "QGChannel variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let QG = request.QGChannel.clone().unwrap();
            let QGvec: Vec<_> = QG.split(",").collect();
            let Q = &QGvec[0]; 
            let G = &QGvec[1];
            let mut pipe  = Popen::create(&[
                "python3",  "-u", "main.py", "generateNewElGamalPubKey", &Q, &G
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
            return (status, Some(out.expect("not string").to_string()));
        }
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
    SwapTicketID: Option<String>,
    swapAmount: Option<String>,
    ENCInit: Option<String>,
    ENCFin:  Option<String>,
    SwapFileName: Option<String>,
    boxID: Option<String>,
    FileContents: Option<String>,
    DECSwapFileName: Option<String>,
    fileName: Option<String>,
    Key: Option<String>,
    Value: Option<String>,
    ErgoTestnetNodeURL: Option<String>,
    ErgoMnemonic: Option<String>,
    ErgoMnemonicPass: Option<String>,
    ErgoSenderEIP3Secret: Option<String>,
    ErgoSenderPubKey: Option<String>,
    ErgoAPIURL: Option<String>,
    FullDirPath: Option<String>, 
    FullEnvPath: Option<String>,
    SepoliaSenderAddr: Option<String>,
    SepoliaPrivKey: Option<String>,
    Sepolia: Option<String>,
    SepoliaID: Option<String>,
    SepoliaScan: Option<String>,
    SolidityCompilerVersion: Option<String>,
    QGChannel: Option<String>
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

