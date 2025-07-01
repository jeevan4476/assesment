use base64;
use bs58;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer};
use solana_sdk::system_instruction;
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction as token_instruction;
use std::convert::Infallible;

#[derive(Serialize)]
struct ResponseKeypair {
    success: bool,
    data: DataKeypair,
}

#[derive(Serialize)]
struct DataKeypair {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct ReqSign {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct ResSign {
    success: bool,
    data: Option<DataSign>,
    error: Option<String>,
}

#[derive(Serialize)]
struct DataSign {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct ReqVerify {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct ResVerify {
    success: bool,
    data: Option<DataVerify>,
    error: Option<String>,
}

#[derive(Serialize)]
struct DataVerify {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SolReq {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SolRes {
    success: bool,
    data: Option<SolData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SolData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}
#[derive(Deserialize)]
struct TokenReq {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    isSigner: bool,
}

#[derive(Serialize)]
struct TokenData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SendTokenResponse {
    success: bool,
    data: Option<TokenData>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintReq {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenAccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenRes {
    success: bool,
    data: Option<TokenInstructionData>,
    error: Option<String>,
}

#[derive(Serialize)]
struct TokenInstructionData {
    program_id: String,
    accounts: Vec<TokenAccountInfo>,
    instruction_data: String,
}

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let (method, path) = (req.method(), req.uri().path());

    match (method, path) {
        (&Method::POST, "/keypair") => {
            let keypair = Keypair::new();
            let pubkey = keypair.pubkey().to_string();
            let secret = bs58::encode(keypair.to_bytes()).into_string();

            let response = ResponseKeypair {
                success: true,
                data: DataKeypair { pubkey, secret },
            };

            let json = serde_json::to_string(&response).unwrap();

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .status(StatusCode::OK)
                .body(Body::from(json))
                .unwrap())
        }
        (&Method::POST, "/send/sol") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<SolReq, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(req_data) => {
                    let from = req_data.from.parse::<Pubkey>();
                    let to = req_data.to.parse::<Pubkey>();

                    if let (Ok(from_pubkey), Ok(to_pubkey)) = (from, to) {
                        let ix: Instruction = system_instruction::transfer(
                            &from_pubkey,
                            &to_pubkey,
                            req_data.lamports,
                        );

                        let encoded_data = base64::encode(&ix.data);

                        let data = SolData {
                            program_id: ix.program_id.to_string(),
                            accounts: ix.accounts.iter().map(|a| a.pubkey.to_string()).collect(),
                            instruction_data: encoded_data,
                        };

                        let json = serde_json::to_string(&SolRes {
                            success: true,
                            data: Some(data),
                            error: None,
                        })
                        .unwrap();

                        return Ok(Response::builder()
                            .header("Content-Type", "application/json")
                            .status(StatusCode::OK)
                            .body(Body::from(json))
                            .unwrap());
                    }

                    let err_json = serde_json::to_string(&SolRes {
                        success: false,
                        data: None,
                        error: Some("Invalid from or to public keys".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err_json))
                        .unwrap())
                }

                Err(_) => {
                    let err_json = serde_json::to_string(&SolRes {
                        success: false,
                        data: None,
                        error: Some("Missing or invalid fields provided".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err_json))
                        .unwrap())
                }
            }
        }

        (&Method::POST, "/send/token") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<TokenReq, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(req_data) => {
                    let to = req_data.destination.parse::<Pubkey>();
                    let mint = req_data.mint.parse::<Pubkey>();
                    let owner = req_data.owner.parse::<Pubkey>();

                    if let (Ok(dest_pubkey), Ok(mint_pubkey), Ok(owner_pubkey)) = (to, mint, owner)
                    {
                        let from_token_account =
                            get_associated_token_address(&owner_pubkey, &mint_pubkey);
                        let to_token_account =
                            get_associated_token_address(&dest_pubkey, &mint_pubkey);

                        let ix_result = token_instruction::transfer(
                            &spl_token::id(),
                            &from_token_account,
                            &to_token_account,
                            &owner_pubkey,
                            &[],
                            req_data.amount,
                        );

                        if let Ok(ix) = ix_result {
                            let data = TokenData {
                                program_id: ix.program_id.to_string(),
                                accounts: ix
                                    .accounts
                                    .iter()
                                    .map(|a| AccountInfo {
                                        pubkey: a.pubkey.to_string(),
                                        isSigner: a.is_signer,
                                    })
                                    .collect(),
                                instruction_data: base64::encode(&ix.data),
                            };

                            let json = serde_json::to_string(&SendTokenResponse {
                                success: true,
                                data: Some(data),
                                error: None,
                            })
                            .unwrap();

                            return Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .status(StatusCode::OK)
                                .body(Body::from(json))
                                .unwrap());
                        }
                    }

                    let err = serde_json::to_string(&SendTokenResponse {
                        success: false,
                        data: None,
                        error: Some("Invalid public keys".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err))
                        .unwrap())
                }

                Err(_) => {
                    let err = serde_json::to_string(&SendTokenResponse {
                        success: false,
                        data: None,
                        error: Some("Missing or invalid fields provided".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err))
                        .unwrap())
                }
            }
        }

        (&Method::POST, "/message/sign") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<ReqSign, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(sign_req) => {
                    let decoded_res = bs58::decode(sign_req.secret).into_vec();

                    if let Ok(secret_bytes) = decoded_res {
                        if secret_bytes.len() == 64 {
                            if let Ok(keypair) = Keypair::from_bytes(&secret_bytes) {
                                let signature = keypair.sign_message(sign_req.message.as_bytes());
                                let signature_base64 = base64::encode(signature.as_ref());

                                let data = DataSign {
                                    signature: signature_base64,
                                    public_key: keypair.pubkey().to_string(),
                                    message: sign_req.message,
                                };

                                let json = serde_json::to_string(&ResSign {
                                    success: true,
                                    data: Some(data),
                                    error: None,
                                })
                                .unwrap();

                                return Ok(Response::builder()
                                    .header("Content-Type", "application/json")
                                    .status(StatusCode::OK)
                                    .body(Body::from(json))
                                    .unwrap());
                            }
                        }
                    }

                    let error_json = serde_json::to_string(&ResSign {
                        success: false,
                        data: None,
                        error: Some("Invalid secret key format".into()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }

                Err(_) => {
                    let error_json = json!({
                        "success": false,
                        "error": "Missing required fields"
                    })
                    .to_string();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }
            }
        }

        (&Method::POST, "/token/mint") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<MintReq, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(req_data) => {
                    let mint_pubkey = req_data.mint.parse::<Pubkey>();
                    let authority_pubkey = req_data.authority.parse::<Pubkey>();
                    let destination_pubkey = req_data.destination.parse::<Pubkey>();

                    if let (Ok(mint), Ok(authority), Ok(destination_owner)) =
                        (mint_pubkey, authority_pubkey, destination_pubkey)
                    {
                        let destination_token_account =
                            get_associated_token_address(&destination_owner, &mint);

                        let ix = spl_token::instruction::mint_to(
                            &spl_token::id(),
                            &mint,
                            &destination_token_account,
                            &authority,
                            &[],
                            req_data.amount,
                        );

                        if let Ok(ix) = ix {
                            let accounts = ix
                                .accounts
                                .iter()
                                .map(|a| TokenAccountInfo {
                                    pubkey: a.pubkey.to_string(),
                                    is_signer: a.is_signer,
                                    is_writable: a.is_writable,
                                })
                                .collect();

                            let json = serde_json::to_string(&TokenRes {
                                success: true,
                                data: Some(TokenInstructionData {
                                    program_id: ix.program_id.to_string(),
                                    accounts,
                                    instruction_data: base64::encode(&ix.data),
                                }),
                                error: None,
                            })
                            .unwrap();

                            return Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .status(StatusCode::OK)
                                .body(Body::from(json))
                                .unwrap());
                        }
                    }

                    let err = serde_json::to_string(&TokenRes {
                        success: false,
                        data: None,
                        error: Some("Invalid public keys".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err))
                        .unwrap())
                }

                Err(_) => {
                    let err = serde_json::to_string(&TokenRes {
                        success: false,
                        data: None,
                        error: Some("Missing or invalid fields".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err))
                        .unwrap())
                }
            }
        }

        (&Method::POST, "/message/verify") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<ReqVerify, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(verify_req) => {
                    let pubkey_result = verify_req.pubkey.parse::<Pubkey>();
                    let sig_result = base64::decode(&verify_req.signature);

                    if let (Ok(pubkey), Ok(signature_bytes)) = (pubkey_result, sig_result) {
                        if let Ok(signature) = Signature::try_from(signature_bytes.as_slice()) {
                            let valid =
                                signature.verify(pubkey.as_ref(), verify_req.message.as_bytes());

                            let data = DataVerify {
                                valid,
                                message: verify_req.message,
                                pubkey: pubkey.to_string(),
                            };

                            let json = serde_json::to_string(&ResVerify {
                                success: true,
                                data: Some(data),
                                error: None,
                            })
                            .unwrap();

                            return Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .status(StatusCode::OK)
                                .body(Body::from(json))
                                .unwrap());
                        }
                    }

                    let error_json = serde_json::to_string(&ResVerify {
                        success: false,
                        data: None,
                        error: Some("Invalid pubkey or signature".into()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }

                Err(_) => {
                    let error_json = json!({
                        "success": false,
                        "error": "Missing required fields"
                    })
                    .to_string();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(error_json))
                        .unwrap())
                }
            }
        }

        (&Method::POST, "/token/create") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
            let parsed: Result<TokenRequest, _> = serde_json::from_slice(&body_bytes);

            match parsed {
                Ok(req_data) => {
                    let mint_pubkey = req_data.mint.parse::<Pubkey>();
                    let mint_auth = req_data.mintAuthority.parse::<Pubkey>();

                    if let (Ok(mint), Ok(mint_authority)) = (mint_pubkey, mint_auth) {
                        let ix = spl_token::instruction::initialize_mint(
                            &spl_token::id(),
                            &mint,
                            &mint_authority,
                            None,
                            req_data.decimals,
                        );

                        if let Ok(ix) = ix {
                            let accounts = ix
                                .accounts
                                .iter()
                                .map(|a| TokenAccountInfo {
                                    pubkey: a.pubkey.to_string(),
                                    is_signer: a.is_signer,
                                    is_writable: a.is_writable,
                                })
                                .collect();

                            let json = serde_json::to_string(&TokenRes {
                                success: true,
                                data: Some(TokenInstructionData {
                                    program_id: ix.program_id.to_string(),
                                    accounts,
                                    instruction_data: base64::encode(&ix.data),
                                }),
                                error: None,
                            })
                            .unwrap();

                            return Ok(Response::builder()
                                .header("Content-Type", "application/json")
                                .status(StatusCode::OK)
                                .body(Body::from(json))
                                .unwrap());
                        }
                    }

                    let err = serde_json::to_string(&TokenRes {
                        success: false,
                        data: None,
                        error: Some("Invalid public keys".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err))
                        .unwrap())
                }

                Err(_) => {
                    let err = serde_json::to_string(&TokenRes {
                        success: false,
                        data: None,
                        error: Some("Missing or invalid fields provided".to_string()),
                    })
                    .unwrap();

                    Ok(Response::builder()
                        .header("Content-Type", "application/json")
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(err))
                        .unwrap())
                }
            }
        }
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() {
    let address = ([127, 0, 0, 1], 3000).into();

    let maker =
        make_service_fn(|_connection| async { Ok::<_, Infallible>(service_fn(handle_request)) });

    let server = Server::bind(&address).serve(maker);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
