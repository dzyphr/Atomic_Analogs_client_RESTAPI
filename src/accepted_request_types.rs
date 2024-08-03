pub fn private_accepted_request_types() -> Vec<&'static str>
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
        "generateElGKeySpecificQG",
        "logInToPasswordEncryptedAccount",
        "reloadAllSwapStates", 
        "startSwapFromUI",
        "get_responderJSONbySwapID"
    ]
}

pub fn public_accepted_request_types() -> Vec<&'static str>
{
    return vec![
    ]
}

