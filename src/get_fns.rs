use crate::{readJSONfromfilepath, json, Path, File, Storage, Html, Read};

pub async fn get_ElGamalPubs() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalPubKeys.json";
    readJSONfromfilepath(filepath).await
}

pub async fn get_ElGamalQChannels() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "ElGamalQChannels.json";
    readJSONfromfilepath(filepath).await
}

pub async fn get_QPubkeyArray() -> Result<impl warp::Reply, warp::Rejection>
{
    let filepath = "QPubkeyArray.json";
    readJSONfromfilepath(filepath).await
}

pub async fn private_get_request_map(
    storage: Storage,
    apikey: Html<&str>
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let result = storage.request_map.read();
        Ok(warp::reply::json(&*result))
}

