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
use reqwest::Error;
use tokio::runtime::Runtime;
mod json_fns;
use json_fns::{json_body, delete_json};
mod API_keys;
use API_keys::{accepted_private_api_keys, accepted_public_api_keys};
mod accepted_request_types;
use accepted_request_types::{private_accepted_request_types, public_accepted_request_types};
mod get_fns;
use get_fns::{private_get_request_map, get_QGPubkeyArray, get_ElGamalQGChannels, get_ElGamalPubs}; 
mod json_tools;
use json_tools::{readJSONfromfilepath, readJSONfromString};
mod delete_fns;
use delete_fns::{private_delete_request};
mod update_fns;
use update_fns::{private_update_request_map};
mod swap_fns;
use swap_fns::{makeSwapDir};
mod str_tools;
use str_tools::{rem_first_and_last};

fn getAllEnabledChainsVec() -> Vec<&'static str>
{
    return vec![
        "TestnetErgo",
        "Sepolia"
    ];
}

fn accountNameFromChainAndIndex(chain: &str, index: usize, getSize: bool) -> Result<String, String> {
    if chain == "TestnetErgo" {
        let account_vec = vec![
            "responderEnv"
        ];
        if !getSize {
            if let Some(account) = account_vec.get(index) {
                return Ok(account.to_string());
            } else {
                return Err("Index out of bounds".to_string());
            }
        } else {
            return Ok(account_vec.len().to_string());
        }
    } else if chain == "Sepolia" {
        let account_vec = vec![
            "basic_framework"
        ];
        if !getSize {
            if let Some(account) = account_vec.get(index) {
                return Ok(account.to_string());
            } else {
                return Err("Index out of bounds".to_string());
            }
        } else {
            return Ok(account_vec.len().to_string());
        }
    } else {
        return Err("Chain not found".to_string());
    }
}


fn getAllAccountsVec() -> Vec<String>
{
    let allEnabledChains = getAllEnabledChainsVec();
    let mut allChainAccountsVec = vec![];
    for chain in allEnabledChains
    {
        let currentChainNumberOfAccounts = accountNameFromChainAndIndex(chain, 0, true);
        let mut u32_currentChainNumberOfAccounts = currentChainNumberOfAccounts.unwrap().parse::<u32>().unwrap();
        while u32_currentChainNumberOfAccounts.clone() > 0
        {
            allChainAccountsVec.push(
                accountNameFromChainAndIndex(
                    chain, u32_currentChainNumberOfAccounts.clone() as usize, false
                ).unwrap()
            );
            u32_currentChainNumberOfAccounts = u32_currentChainNumberOfAccounts.clone() - 1
        }
    }
    return allChainAccountsVec;
}

fn getAllAcountsMap() -> HashMap<String, String>
{
    let allEnabledChains = getAllEnabledChainsVec();
    let mut allChainAccountsMap = HashMap::new();
    let mut chainFrameworkPath = String::new();
    for chain in allEnabledChains
    {
        if chain == "TestnetErgo"
        {
            chainFrameworkPath = "Ergo/SigmaParticle/".to_string();
        }
        else if chain == "Sepolia"
        {
            chainFrameworkPath = "EVM/Atomicity/".to_string()
        }
        let currentChainNumberOfAccounts = accountNameFromChainAndIndex(chain, 0, true);
        let mut u32_currentChainNumberOfAccounts = currentChainNumberOfAccounts.unwrap().parse::<u32>().unwrap();
        while u32_currentChainNumberOfAccounts.clone() > 0
        {
            let index = <u32 as TryInto<usize>>::try_into(u32_currentChainNumberOfAccounts.clone()).unwrap() - 1;
            let currentAccount = 
                accountNameFromChainAndIndex(
                    chain, index, false
                ).unwrap();
            let reg_env_path = 
                chainFrameworkPath.clone() + 
                &currentAccount + 
                "/.env";
            let enc_env_path = 
                chainFrameworkPath.clone() +
                &currentAccount +
                "/.env.encrypted";
            if Path::new(&reg_env_path).exists()
            {
                allChainAccountsMap.insert(reg_env_path, currentAccount);
            }
            else if Path::new(&enc_env_path).exists()
            {
                allChainAccountsMap.insert(enc_env_path, currentAccount);
            }
            u32_currentChainNumberOfAccounts = u32_currentChainNumberOfAccounts.clone() - 1
        }
    }
    allChainAccountsMap
}

fn StringStringMap_to_json_String(map: HashMap<String, String>) -> String
{
    let json_map: Map<String, Value> = map
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();
     serde_json::to_string(&json_map).unwrap()
}

pub async fn get_allChainAccountsMapJSON() -> Result<impl warp::Reply, warp::Rejection>
{
    let allAccountsMap = getAllAcountsMap();
    let allAcountsMapJSONString = StringStringMap_to_json_String(allAccountsMap);
    readJSONfromString(allAcountsMapJSONString).await
}

//we need a more descriptive obj
//lets get:
//each chain
//each account per chain
//check the path of each account according to chain framework path
//check if its .enc or not
//save into a map that looks like
//{
//  "accountname1": "fullenvpath1",
//  "accountname2": "fullenvpath2"
//}
//this obj gets sent back when called for by the UI to load existing accounts
//still need to figure initial part where all folders except expected are checked for as accounts


fn checkAccountLoggedInStatus(encEnvPath: &str, storage: Storage) -> bool
{
    let s = storage.loggedInAccountMap.read().clone();
    return s.contains_key(encEnvPath)
}

#[tokio::main]
async fn main() {
    let version =  "v0.0.1";
    let main_path  = "requests";
//    let public_main_path = "publicrequests"; //might never need this until client features include server hosting type abilities
//    let OrderTypesPath = "ordertypes";
    let ElGamalPubsPath = "ElGamalPubs";
    let ElGamalQChannelsPath = "ElGamalQGChannels";
    let QGPubkeyArrayPath = "QGPubkeyArray";
    let AllChainAccountsMapPath = "AllChainAccountsMap";
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
    let get_ElGamalQGChannels = warp::get()
        .and(warp::path(version))
        .and(warp::path(ElGamalQChannelsPath))
        .and(warp::path::end())
        .and_then(get_ElGamalQGChannels)
        .with(cors.clone());
    let get_QGPubkeyArray = warp::get()
        .and(warp::path(version))
        .and(warp::path(QGPubkeyArrayPath))
        .and(warp::path::end())
        .and_then(get_QGPubkeyArray)
        .with(cors.clone());
    let get_AllChainAccountsMap = warp::get()
        .and(warp::path(version))
        .and(warp::path(AllChainAccountsMapPath))
        .and(warp::path::end())
        .and_then(get_allChainAccountsMapJSON)
        .with(cors.clone());        
    let routes = 
        add_requests.or(get_requests).or(update_request).or(private_delete_request)
        .or(get_ElGamalPubs).or(get_ElGamalQGChannels).or(get_QGPubkeyArray).or(get_AllChainAccountsMap);
    warp::serve(routes)
        .run(([127, 0, 0, 1], 3031))
        .await;
}

async fn handle_request(request: Request, storage: Storage) -> (bool, Option<String>)
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
        let responderCrossChainAccountName = accountNameFromChainAndIndex(&request.responderCrossChain.clone().unwrap(), 0, false);
        let responderLocalChainAccountName = accountNameFromChainAndIndex(&request.responderLocalChain.clone().unwrap(), 0, false);
        let mut localChainAccountPassword = String::new();
        let mut crossChainAccountPassword = String::new();
        let mut InitiatorChain = request.responderCrossChain.clone().unwrap();
        let mut ResponderChain = request.responderLocalChain.clone().unwrap();
        dbg!(&InitiatorChain);
        dbg!(&ResponderChain);
        if InitiatorChain == "TestnetErgo"
        {
            let chainFrameworkPath = "Ergo/SigmaParticle/";
            let encEnvPath = chainFrameworkPath.to_owned() + &responderCrossChainAccountName.clone().unwrap() + "/.env.encrypted";
            dbg!(&encEnvPath);
            let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                true
            } else {
                false
            };
            if exists
            {
                if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                {
                    crossChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                }
                else
                {
                    let errstr = InitiatorChain.to_owned() + " " +  &responderCrossChainAccountName.clone().unwrap() + " is not logged in!";
                    dbg!(&errstr);
                    return (false, Some(errstr.to_string()))
                }
            }
        }
        if ResponderChain == "Sepolia"
        {
            let chainFrameworkPath = "EVM/Atomicity/";
            let encEnvPath = chainFrameworkPath.to_owned() + &responderLocalChainAccountName.clone().unwrap() + "/.env.encrypted";
            dbg!(&encEnvPath);
            let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                true
            } else {
                false
            };
            if exists
            {
                if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                {
                    localChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                }
                else
                {
                    let errstr = ResponderChain.to_owned() + " " + &responderLocalChainAccountName.unwrap() + " is not logged in!";
                    dbg!(&errstr);
                    return (false, Some(errstr.to_string()))
                }
            }
        }
        if localChainAccountPassword == String::new() && crossChainAccountPassword == String::new()
        {
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "GeneralizeENC_ResponseSubroutine",
                &swapName, &responderCrossChainAccountName.unwrap(),
                &responderLocalChainAccountName.unwrap().clone(), &request.ElGamalKey.clone().unwrap(), 
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
        }
        else
        {
            //TODO ENC account endpoint usage with args
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "GeneralizeENC_ResponseSubroutine",
                &swapName, &responderCrossChainAccountName.unwrap(),
                &responderLocalChainAccountName.unwrap().clone(), &request.ElGamalKey.clone().unwrap(),
                &request.ElGamalKeyPath.clone().unwrap(), &request.responderCrossChain.clone().unwrap(),
                &request.responderLocalChain.clone().unwrap(), &request.swapAmount.clone().unwrap(),
                &localChainAccountPassword, &crossChainAccountPassword
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
                        .arg(localChainAccountPassword)
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
        }
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
        /*
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
        }*/
        makeSwapDir(&request.SwapTicketID.clone().unwrap(), &request.ENCInit.clone().unwrap());
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
            let mut file_path = request.SwapTicketID.clone().unwrap() + "/responder.json";
            let mut responderJSONContents = fs::read_to_string(file_path).expect("error reading file");
            let json_object: Value = serde_json::from_str(&responderJSONContents).expect("Invalid JSON");
            let InitiatorChain = json_object["InitiatorChain"].to_string().replace("\"", "");
            let ResponderChain = json_object["ResponderChain"].to_string().replace("\"", "");
            let mut localChainAccountPassword = String::new();
            let mut crossChainAccountPassword = String::new();
            let responderCrossChainAccountName = accountNameFromChainAndIndex(&InitiatorChain.clone(), 0, false);
            let responderLocalChainAccountName = accountNameFromChainAndIndex(&ResponderChain.clone(), 0, false);
            dbg!(&InitiatorChain);
            dbg!(&ResponderChain);
            if InitiatorChain == "TestnetErgo"
            {
                let chainFrameworkPath = "Ergo/SigmaParticle/";
                let encEnvPath = chainFrameworkPath.to_owned() + &responderCrossChainAccountName.clone().unwrap() + "/.env.encrypted";
                dbg!(&encEnvPath);
                let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                    true
                } else {
                    false
                };
                if exists
                {
                    if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                    {
                        crossChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                    }
                    else
                    {
                        let errstr = InitiatorChain.to_owned() + " " +  &responderCrossChainAccountName.unwrap() + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                }
            }
            if ResponderChain == "Sepolia"
            {
                let chainFrameworkPath = "EVM/Atomicity/";
                let encEnvPath = chainFrameworkPath.to_owned() + &responderLocalChainAccountName.clone().unwrap() + "/.env.encrypted";
                dbg!(&encEnvPath);
                let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                    true
                } else {
                    false
                };
                if exists
                {
                    if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                    {
                        localChainAccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                    }
                    else
                    {
                        let errstr = ResponderChain.to_owned() + " " + &responderLocalChainAccountName.unwrap() + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                }
            }
            if localChainAccountPassword == String::new() && crossChainAccountPassword == String::new()
            {
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
            }
            else
            {
                let responderJSONPath = request.SwapTicketID.clone().unwrap() + "/responder.json";
                let mut pipe = Popen::create(&[
                    "python3",  "-u", "main.py", 
                    "GeneralizedENC_ResponderClaimSubroutine", &responderJSONPath,
                    &localChainAccountPassword, &crossChainAccountPassword
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
        if request.swapName == None
        {
            let output = &(output.to_owned() + "swapName variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let ErgoAccountName = accountNameFromChainAndIndex("TestnetErgo", 0, false);
            let chainFrameworkPath = "Ergo/SigmaParticle/";
            let encEnvPath = chainFrameworkPath.to_owned() + &ErgoAccountName.clone().unwrap() + "/.env.encrypted";
            dbg!(&encEnvPath);
            let exists = if let Ok(_) = fs::metadata(encEnvPath.clone()) {
                true
            } else {
                false
            };
            let mut AccountPassword = String::new();
            if exists
            {
                if checkAccountLoggedInStatus(&encEnvPath, storage.clone()) == true
                {
                    AccountPassword = storage.loggedInAccountMap.read()[&encEnvPath].clone();
                }
                else
                {
                    let errstr =  "TestnetErgo ".to_owned() +  &ErgoAccountName.unwrap() + " is not logged in!";
                    dbg!(&errstr);
                    return (false, Some(errstr.to_string()))
                }
                let mut pipe = Popen::create(&[
                    "python3",  "-u", "main.py", 
                    "SigmaParticle_box_to_addr", 
                    &request.boxID.clone().unwrap(), 
                    &request.swapName.clone().unwrap(),
                    &AccountPassword
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
            else
            {

                let mut pipe = Popen::create(&[
                    "python3",  "-u", "main.py", "SigmaParticle_box_to_addr", 
                    &request.boxID.clone().unwrap(),
                    &request.swapName.clone().unwrap()
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
        if request.CrossChain == None
        {
            let output = &(output.to_owned() + "crossChain variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            if request.CrossChain.clone().unwrap() == "Sepolia"
            {
                let ErgoAccountName = accountNameFromChainAndIndex("TestnetErgo", 0, false);
                let ergchainFrameworkPath = "Ergo/SigmaParticle/";
                let ergencEnvPath = ergchainFrameworkPath.to_owned() + &ErgoAccountName.clone().unwrap() + "/.env.encrypted";
                dbg!(&ergencEnvPath);
                let ergoencenvexists = if let Ok(_) = fs::metadata(ergencEnvPath.clone()) {
                    true
                } else {
                    false
                };
                let mut ErgoAccountPassword = String::new();
                let SepoliaAccountName = accountNameFromChainAndIndex("Sepolia", 0, false);
                let sepoliachainFrameworkPath = "EVM/Atomicity/";
                let sepoliaencEnvPath = sepoliachainFrameworkPath.to_owned() + &SepoliaAccountName.clone().unwrap() + "/.env.encrypted";
                dbg!(&sepoliaencEnvPath);
                let sepoliaencenvexists = if let Ok(_) = fs::metadata(sepoliaencEnvPath.clone()) {
                    true
                } else {
                    false
                };
                let mut SepoliaAccountPassword = String::new();
                if ergoencenvexists && sepoliaencenvexists
                {
                    if checkAccountLoggedInStatus(&ergencEnvPath, storage.clone()) == true
                    {
                        ErgoAccountPassword = storage.loggedInAccountMap.read()[&ergencEnvPath].clone();
                    }
                    else
                    {
                        let errstr =  "TestnetErgo ".to_owned() +  &ErgoAccountName.unwrap() + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                    if checkAccountLoggedInStatus(&sepoliaencEnvPath, storage.clone()) == true
                    {
                        SepoliaAccountPassword = storage.loggedInAccountMap.read()[&sepoliaencEnvPath].clone();
                    }
                    else
                    {
                        let errstr =  "Sepolia ".to_owned() +  &SepoliaAccountName.unwrap() + " is not logged in!";
                        dbg!(&errstr);
                        return (false, Some(errstr.to_string()))
                    }
                    let mut pipe = Popen::create(&[
                        "python3",  "-u", "main.py", "checkBoxValue", &request.boxID.clone().unwrap(),
                        &(request.SwapTicketID.clone().unwrap() + "/" + 
                          &request.fileName.clone().unwrap()), &request.SwapTicketID.clone().unwrap(),
                        &ErgoAccountPassword, &SepoliaAccountPassword
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
            else
            {
                let errstring: String = "Unhandled Cross Chain:".to_owned() + &request.CrossChain.clone().unwrap();
                return (status, Some(errstring));
            }
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
    if request.request_type == "logInToPasswordEncryptedAccount"
    {
        status = true;
        if request.Chain == None
        {
            let output = &(output.to_owned() + "Chain variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.AccountName == None
        {
            let output = &(output.to_owned() + "AccountName variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.Password == None
        {
            let output = &(output.to_owned() + "Password variable is required!");
            return (status, Some(output.to_string()));
        }
        else
        {
            let mut chainFrameworkPath = String::new();
            if request.Chain.clone().unwrap() == "TestnetErgo"
            {
                chainFrameworkPath = "Ergo/SigmaParticle/".to_string();
            }
            if request.Chain.clone().unwrap() == "Sepolia"
            {
                chainFrameworkPath = "EVM/Atomicity/".to_string();
            }
            let enc_env_path = chainFrameworkPath + &request.AccountName.clone().unwrap() + "/.env.encrypted";
            let mut pipe = Popen::create(&[
                "python3",  "-u", "main.py", "proveEncEnvFilePasswordKnowledge",
                &enc_env_path, &request.Password.clone().unwrap()
            ], PopenConfig{
                stdout: Redirection::Pipe, ..Default::default()}).expect("err");
            let (out, err) = pipe.communicate(None).expect("err");
            if let Some(exit_status) = pipe.poll()
            {
                println!("Out: {:?}, Err: {:?}", out, err);
                if out == Some("True\n".to_string())
                {
//                    println!("PasswordKnowledgeProven");
                    storage.loggedInAccountMap.write().insert(enc_env_path, request.Password.clone().unwrap());
                    dbg!(&storage.loggedInAccountMap);
                }
                //push success cases to loggedInAccountMap here
            }
            else
            {
                pipe.terminate().expect("err");
            }
            return (status, Some(out.expect("not string").to_string().replace("\n", "")))
        }
    }
    if request.request_type == "hotReloadAllSwapStates"
    {
        status = true;
        let possible_swap_states = vec![
            "initiated", "uploadingResponseContract", "uploadedResponseContract", 
            "fundingResponseContract", "fundedResponseContract", "responding", 
            "responded", "finalized", "verifyingFinalizedContractValues", 
            "verifiedFinalizedContractValues", "claiming", "refunding", 
            "claimed", "refunded", "terminated", "tbd"
        ];
        let current_dir = Path::new(".");
        let mut uuid_dirs = vec![];
        let mut swapstatemap = HashMap::<String, String>::new();
        if let Ok(subdirs) = fs::read_dir(current_dir)
        {
            for subdir in subdirs
            {
                if let Ok(subdir) = subdir
                {
                    let file_name = subdir.file_name().to_string_lossy().into_owned();
                    if let Some(name) = Some(file_name.clone())
                    {   
                        if let Ok(uuid) = Uuid::parse_str(&name.clone())
                        {
                            dbg!(&name.clone());
                            uuid_dirs.push(name.clone());
                            /*if uuid.get_version() == Some(uuid::Version::Md5) //this check for
                             * specific version doesnt currently work but is possible
                            {
                            }*/
                        }
                    }
                }
            }
        };
        if uuid_dirs.is_empty()
        {
            //if its still empty we have 0 swap folders to reload so return that as a message
            return (status, Some("No Swap Folders Found".to_string()));
        }
        for dir in uuid_dirs
        {
            //TODO get local and cross chain account name from resp_J
            //check if enc env files if so check if logged in before running
            //call with passwords when available
            //
            let resp_J_path = dir.to_string() + "/responder.json";
            if Path::new(&resp_J_path).exists() == true
            {
                let resp_J = fs::read_to_string(resp_J_path.clone()).expect("Failed to read file");
                let v: Value = serde_json::from_str(&resp_J).expect("failed to parse JSON");
                let InitiatorChain = &v["InitiatorChain"];
                let ResponderChain = &v["ResponderChain"];
                if InitiatorChain == "TestnetErgo" && ResponderChain == "Sepolia"
                {
                    let responderErgoAccountName = &v["responderErgoAccountName"];
                    let responderSepoliaAccountName = &v["responderSepoliaAccountName"];
                    let ErgoAccountName = responderErgoAccountName.to_string().replace(r#"\""#, "").replace(r#"""#, "");
                    let ergchainFrameworkPath = "Ergo/SigmaParticle/";
                    let ergencEnvPath = ergchainFrameworkPath.to_owned() + &ErgoAccountName.clone() + "/.env.encrypted";
                    dbg!(&ergencEnvPath);
                    let ergoencenvexists = if let Ok(_) = fs::metadata(ergencEnvPath.clone()) {
                        true
                    } else {
                        false
                    };
                    let mut ErgoAccountPassword = String::new();
                    let SepoliaAccountName = responderSepoliaAccountName.to_string().replace(r#"\""#, "").replace(r#"""#, "");
                    let sepoliachainFrameworkPath = "EVM/Atomicity/";
                    let sepoliaencEnvPath = sepoliachainFrameworkPath.to_owned() + &SepoliaAccountName.clone() + "/.env.encrypted";
                    dbg!(&sepoliaencEnvPath);
                    let sepoliaencenvexists = if let Ok(_) = fs::metadata(sepoliaencEnvPath.clone()) {
                        true
                    } else {
                        false
                    };
                    let mut SepoliaAccountPassword = String::new();
                    if ergoencenvexists && sepoliaencenvexists
                    {
                        if checkAccountLoggedInStatus(&ergencEnvPath, storage.clone()) == true
                        {
                            ErgoAccountPassword = storage.loggedInAccountMap.read()[&ergencEnvPath].clone();
                        }
                        else
                        {
                            let errstr =  "TestnetErgo ".to_owned() +  &ErgoAccountName + " is not logged in!";
                            dbg!(&errstr);
                            break
    //                        return (false, Some(errstr.to_string()))
                        }
                        if checkAccountLoggedInStatus(&sepoliaencEnvPath, storage.clone()) == true
                        {
                            SepoliaAccountPassword = storage.loggedInAccountMap.read()[&sepoliaencEnvPath].clone();
                        }
                        else
                        {
                            let errstr =  "Sepolia ".to_owned() +  &SepoliaAccountName + " is not logged in!";
                            dbg!(&errstr);
                            break
    //                        return (false, Some(errstr.to_string()))
                        }
                    }
                    let SwapStatePath = dir.to_string() + "/SwapState";
                    let SwapState = fs::read_to_string(SwapStatePath).expect("Failed to read file");
                    swapstatemap.insert(dir.to_string(), SwapState.clone());
                        
                    let (out, updatedswapstatemap) = match possible_swap_states.iter().enumerate().find(|(_, &x)| x == SwapState) {
                        Some((index, _)) => {
                            match index {
                                0..=5 => 
                                    GeneralizeENC_ResponseSubroutine_hotreload(
                                        dir.to_string(), SwapState.to_string(),
                                        SepoliaAccountPassword.clone().to_string(), ErgoAccountPassword.clone().to_string(),
                                        swapstatemap.clone()
                                    ),
                                6..=10 => 
                                    GeneralizedENC_ResponderClaimSubroutine_hotreload(
                                        dir.to_string(),
                                        resp_J_path.to_string(), SwapState.to_string(),
                                        swapstatemap.clone(),
                                        SepoliaAccountPassword.clone().to_string(), ErgoAccountPassword.clone().to_string()
                                    ),
                                _ => {
                                    // Handle other cases
                                    ("unhandled swap state".to_string(), swapstatemap)
                                }
                            }
                        },
                        None => {
                            // Handle case when SwapState is not found in possible_swap_states
                            ("unknown swap state".to_string(), swapstatemap)
                        }
                    };
                    swapstatemap = updatedswapstatemap;

                    fn GeneralizeENC_ResponseSubroutine_hotreload(
                        dir: String, SwapState: String, SepoliaAccountPassword: String, ErgoAccountPassword: String, mut swapstatemap: HashMap<String, String>
                    ) -> (String, HashMap<String, String>)
                    {
                        let mut pipe = Popen::create(&[
                            "python3",  "-u", "main.py", "GeneralizeENC_ResponseSubroutine_hotreload", &dir,
                            &ErgoAccountPassword, &SepoliaAccountPassword, &SwapState
                        ], PopenConfig{
                            detached: true,
                            stdout: Redirection::Pipe, 
                            ..Default::default()
                        }).expect("err");
                        let (out, err) = pipe.communicate(None).expect("err");
                        if let Some(exit_status) = pipe.poll()
                        {
                            println!("Out: {:?}, Err: {:?}", out, err)
                        }
                        else
                        {
                            pipe.terminate().expect("err");
                        }
                        (out.expect("out is none").to_string(), swapstatemap)
                    }

                    fn GeneralizedENC_ResponderClaimSubroutine_hotreload(
                        dir: String, resp_J_path: String, SwapState: String, 
                        mut swapstatemap: HashMap<String, String>,
                        SepoliaAccountPassword: String , ErgoAccountPassword: String 
                    ) -> (String, HashMap<String, String>)
                    {
                        let possible_swap_states = vec![
                            "initiated", "uploadingResponseContract", "uploadedResponseContract",
                            "fundingResponseContract", "fundedResponseContract", "responding",
                            "responded", "finalized", "verifyingFinalizedContractValues",
                            "verifiedFinalizedContractValues", "claiming", "refunding",
                            "claimed", "refunded", "terminated", "tbd"
                        ];
                        if SwapState == possible_swap_states[6]
                        {
                            let finpathstr = dir.clone() + "/ENC_finalization.bin";
                            let fin_path = Path::new(&finpathstr);
                            if !fin_path.exists()
                            {
                                swapstatemap.insert(dir.to_string(), "responded_unsubmitted".to_string());
                                return ("responded_unsubmitted".to_string(), swapstatemap)
                            }
                            else
                            {
                                dbg!("path exists: ", finpathstr);
                            }
                        }
                        let mut pipe = Popen::create(&[
                            "python3",  "-u", "main.py", "GeneralizedENC_ResponderClaimSubroutine_hotreload", &resp_J_path,
                            &ErgoAccountPassword, &SepoliaAccountPassword, &SwapState
                        ], PopenConfig{
                            detached: true,
                            stdout: Redirection::Pipe, 
                            ..Default::default()
                        }).expect("err");
                        let (out, err) = pipe.communicate(None).expect("err");
                        if let Some(exit_status) = pipe.poll()
                        {
                            println!("Out: {:?}, Err: {:?}", out, err)
                        }
                        else
                        {
                            pipe.terminate().expect("err");
                        }
                        return (out.expect("out is none").to_string(), swapstatemap)
                    }

                }
            }
        }
        //after we reload the swaps the states in the map will change, we need to run an update of
        //the map here to provide accurate data feedback to the UI
        let out = serde_json::to_string(&json!(swapstatemap)).unwrap();
        return (status, Some(out));
        //go through every uuid3 dir
        //get the state, save dirname and state to map to return to UI / caller
        //make an API call depending on the state
        //if a subsequent call is needed to finish the swap we need to determine whether
        //to call it in this logic or let the UI / caller handle it
    }
    if request.request_type == "startSwapFromUI"
    {
        if request.OrderTypeUUID == None
        {
            let output = &(output.to_owned() + "OrderTypeUUID variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.QGChannel == None
        {
            let output = &(output.to_owned() + "QGChannel variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.ElGamalKey == None
        {
            let output = &(output.to_owned() + "ElGamalKey variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.MarketURL == None
        {
            let output = &(output.to_owned() + "MarketURL variable is required!");
            return (status, Some(output.to_string()));
        }
        if request.MarketAPIKey == None
        {
            let output = &(output.to_owned() + "MarketAPIKey variable is required!");
            return (status, Some(output.to_string()));
        }
        status = true;
        let mut swapDataMap: HashMap<String, String> = HashMap::new();
         
        swapDataMap.insert("OrderTypeUUID".to_string(), request.OrderTypeUUID.clone().unwrap().replace("\\", "").replace("\"", ""));
        swapDataMap.insert("QGChannel".to_string(), request.QGChannel.clone().unwrap().replace("\\", "").replace("\"", ""));
        swapDataMap.insert("ElGamalKey".to_string(), request.ElGamalKey.clone().unwrap().replace("\\", "").replace("\"", ""));
        swapDataMap.insert("MarketURL".to_string(), request.MarketURL.clone().unwrap().replace("\\", "").replace("\"", ""));
        swapDataMap.insert("MarketAPIKey".to_string(), request.MarketAPIKey.clone().unwrap().replace("\\", "").replace("\"", ""));
        dbg!(&swapDataMap);

        let requestEncryptedInitiationData = json!({
            "id": Uuid::new_v4().to_string(),
            "request_type": "requestEncryptedInitiation",
            "OrderTypeUUID": swapDataMap["OrderTypeUUID"].replace("\\", "").replace("\"", ""),
            "QGChannel": swapDataMap["QGChannel"].replace("\\", "").replace("\"", ""),
            "ElGamalKey": swapDataMap["ElGamalKey"].replace("\\", "").replace("\"", "")
        });

        let server_public_requests_url = swapDataMap["MarketURL"].replace("ordertypes", "publicrequests").replace("\\", "").replace("\"", "");
        dbg!(&server_public_requests_url);
        let bearer_token = request.MarketAPIKey.clone().unwrap().replace("\\", "").replace("\"", "");
        let response = reqwest::Client::new()
            .post(server_public_requests_url.clone())
            .json(&requestEncryptedInitiationData)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .send()
            .await.expect("failed to POST");
        if response.status().is_success() {
            println!("POST request successful");
            let response_text = response.text().await.expect("failed to get POST response text");
            let jr: Value = serde_json::from_str(&response_text).expect("response text is not json");
            let jr1 = jr.as_str().unwrap(); //can be stored and then parsed as valid json at this point
            let jrobj: Value = serde_json::from_str(&jr1).unwrap();
            let SwapTicketID = jrobj.get("SwapTicketID").expect("SwapTicketID not found").to_string().replace("\\", "").replace("\"", "");
            let ENCinit = jrobj.get("ENC_init.bin").expect("ENC_init.bin not found").to_string();
            makeSwapDir(&SwapTicketID.clone(), &ENCinit.clone());
            //TODO implement proper false result in makeSwapDir use it to determine response here
            swapDataMap.insert("SwapState".to_string(), "initiated".to_string());
            storage.swapStateMap.write().insert(SwapTicketID.clone().to_string(), swapDataMap.clone());
            let swapStateMapString = format!("{:#?}", &*storage.swapStateMap.read());
            fs::write("SwapStateMap", swapStateMapString).expect("Unable to write file");
            //TODO create a function loop that gets called as new swaps are successfully initialized
            //use the loop to keep track of the state and keep communication w server 
            //accordingly, can also use the loop potentially to handle hot reloading
            //for example the loop should see that an initiation occured, create a response 
            //then submit it to the relevant market server and handle the resulting response
            //the loop can call claim or refund depening on what data it has
            //this should be able to handle both hot reloading and basic interaction UX
            return (status, Some("New Swap Dir Created Successfully".to_string()));
        } else {
            println!("POST request failed: {}", response.status());
            return (status, Some("Failed to request Encrypted Initiation".to_string()));
        }
    }
    else
    {
        return  (status, Some("Unknown Error".to_string()));
    }
}

#[derive(Debug)]
pub struct Badapikey;
impl warp::reject::Reject for Badapikey {}

#[derive(Debug)]
pub struct Noapikey;
impl warp::reject::Reject for Noapikey {}

#[derive(Debug)]
pub struct Duplicateid;
impl warp::reject::Reject for Duplicateid {}

#[derive(Debug)]
pub struct Badrequesttype;
impl warp::reject::Reject for Badrequesttype {}


#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Id {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Request {
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
    QGChannel: Option<String>,
    Chain: Option<String>,
    AccountName: Option<String>, 
    Password: Option<String>,
    CrossChain: Option<String>,
    MarketURL: Option<String>,
    OrderTypeUUID: Option<String>,
    MarketAPIKey: Option<String>
}

type StringStringMap = HashMap<String, String>;
type SingleNestMap = HashMap<String, HashMap<String, String>>;

#[derive(Clone)]
pub struct Storage {
   request_map: Arc<RwLock<StringStringMap>>,
   loggedInAccountMap: Arc<RwLock<StringStringMap>>,
   swapStateMap: Arc<RwLock<SingleNestMap>>

}

impl Storage {
    fn new() -> Self {
        Storage {
            request_map: Arc::new(RwLock::new(HashMap::new())),
            loggedInAccountMap: Arc::new(RwLock::new(HashMap::new())),
            swapStateMap: Arc::new(RwLock::new(HashMap::new()))
        }
    }
}

