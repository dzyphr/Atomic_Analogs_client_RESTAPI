use crate::{fs, Request, File, Write};

pub async fn makeSwapDir(SwapTicketID: &str, ENCInit: &str) -> bool
{
    match fs::create_dir(SwapTicketID.clone().to_string()) {
        Ok(_) => println!("Directory created successfully"),
        Err(err) => eprintln!("Error: {}", err),
    }
    let file_path = SwapTicketID.to_owned() + "/ENC_init.bin";
/*    let mut file = match File::create(file_path) {
        Ok(file) => file,
        Err(_) => todo!()
    };
    let data = ENCInit;*/
/*    match file.write_all(data.as_bytes()) {
        Ok(_) => println!("Data written to file successfully"),
        Err(err) => eprintln!("Error: {}", err),
    }*/
    std::fs::write(file_path, ENCInit).expect("Unable to write file");
    return true; //TODO return false on failure
}
