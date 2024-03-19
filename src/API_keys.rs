use crate::{File, Value, Read};

pub fn accepted_private_api_keys() -> Vec<String>
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

pub fn accepted_public_api_keys() -> Vec<&'static str> //no public requests yet
{
    return vec![
    ]
}

