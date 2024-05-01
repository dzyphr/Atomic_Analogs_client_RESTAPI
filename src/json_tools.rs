use crate::{Read, json, File, Path};
pub async fn readJSONfromfilepath(filepath: &str) -> Result<impl warp::Reply, warp::Rejection>
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

pub async fn readJSONfromString(JSONString: String) -> Result<impl warp::Reply, warp::Rejection>
{
    Ok(warp::reply::json(&json!(JSONString)))
}
