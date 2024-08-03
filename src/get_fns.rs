use crate::{readJSONfromfilepath, json, Path, File, Storage, Html, Read, readJSONfromSingleNestMap, load_local_swap_state_map, fs};

pub async fn get_responderJSONbySwapID(SwapID: String) -> String
{
    return fs::read_to_string((&(SwapID + "/responder.json"))).unwrap()
}

pub async fn get_SwapStateMapJSON() -> Result<impl warp::Reply, warp::Rejection>
{
   return readJSONfromSingleNestMap(load_local_swap_state_map()).await
}

pub async fn get_ElGamalPubs() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalPubKeys.json";
    readJSONfromfilepath(filepath).await
}

pub async fn get_ElGamalQGChannels() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalQGChannels.json";
    readJSONfromfilepath(filepath).await
}

pub async fn get_QGPubkeyArray() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "QGPubkeyArray.json";
    readJSONfromfilepath(filepath).await
}



pub async fn private_get_request_map(
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let result = storage.request_map.read();
        Ok(warp::reply::json(&*result))
}

