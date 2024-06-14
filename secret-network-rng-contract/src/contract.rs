use crate::{
    msg::{
        ExecuteMsg, GatewayMsg, InstantiateMsg, QueryMsg, ResponseRetrieveRandomMsg,
    },
    state::{Input, Random, State, CONFIG, STORED_RANDOM},
};
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};
use secret_toolkit::crypto::ContractPrng;
use tnls::{
    msg::{PostExecutionMsg, PrivContractHandleMsg},
    state::Task,
};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = State {
        gateway_address: msg.gateway_address,
        gateway_hash: msg.gateway_hash,
        gateway_key: msg.gateway_key,
    };

    CONFIG.save(deps.storage, &state)?;

    Ok(Response::default())
}

#[entry_point]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let response = match msg {
        ExecuteMsg::Input { message } => try_handle(deps, env, info, message),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::RetrieveRandom {wallet} => try_random_query(deps, wallet),
    };
    pad_query_result(response, BLOCK_SIZE)
}

// acts like a gateway message handle filter
fn try_handle(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: PrivContractHandleMsg,
) -> StdResult<Response> {
    // verify signature with stored gateway public key
    let gateway_key = CONFIG.load(deps.storage)?.gateway_key;
    deps.api
        .secp256k1_verify(
            msg.input_hash.as_slice(),
            msg.signature.as_slice(),
            gateway_key.as_slice(),
        )
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    // determine which function to call based on the included handle
    let handle = msg.handle.as_str();
    match handle {
        "request_random" => try_random(deps, env, msg.input_values, msg.task, msg.input_hash),
        _ => Err(StdError::generic_err("invalid handle".to_string())),
    }
}

fn try_random(
    deps: DepsMut,
    env: Env,
    input_values: String,
    task: Task,
    input_hash: Binary,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;

    let input: Input = serde_json_wasm::from_str(&input_values)
        .map_err(|err| StdError::generic_err(err.to_string()))?;

    let wallet_address = input.wallet_address;

    let random_numbers = input.random_numbers.parse::<u16>()
    .map_err(|err| StdError::generic_err(format!("Invalid index: {}", err)))?;

    let raw_random_u8 = env.block.random.unwrap().0[0]; // Original random number from blockchain
    let entropy_bytes = env.block.time.to_string();
    let entropy = entropy_bytes.as_bytes();
    
    let mut rng = ContractPrng::new(&[raw_random_u8], entropy);

    let rand_bytes = rng.rand_bytes();

    let random_u16 = generate_random_numbers(random_numbers, rand_bytes);

    let random = Random {
        random: random_u16.clone(),
        wallet_address: wallet_address.clone(),
    };

    STORED_RANDOM.add_suffix(wallet_address.as_bytes())
    .insert(deps.storage, &true, &random)?;

    let result = base64::encode(vec_u16_to_string(random_u16));

    let callback_msg = GatewayMsg::Output {
        outputs: PostExecutionMsg {
            result,
            task,
            input_hash,
        },
    }
    .to_cosmos_msg(
        config.gateway_hash,
        config.gateway_address.to_string(),
        None,
    )?;

    Ok(Response::new()
        .add_message(callback_msg)
        .add_attribute("status", "provided RNG complete"))
}

fn try_random_query(deps: Deps, wallet: String) -> StdResult<Binary> {
    let value = STORED_RANDOM
    .add_suffix(wallet.as_bytes())
.get(deps.storage, &true)
        .ok_or_else(|| StdError::generic_err("Value not found"))?;

    to_binary(&ResponseRetrieveRandomMsg {
        random_numbers: value.random.clone(),
    })
}
fn generate_random_numbers(count: u16, seed_array: [u8; 32]) -> Vec<u16> {
    let mut random_numbers = Vec::with_capacity(count as usize);
    let mut seed_index = 0;

    for _ in 0..count {
        // Combine two u8 values to form a u16 value
        let raw_value = ((seed_array[seed_index] as u16) << 8) | (seed_array[(seed_index + 1) % 32] as u16);
        
        // Scale the value to the range 1 to count (inclusive)
        let value = 1 + (raw_value % count);
        random_numbers.push(value);
        
        // Move to the next index in the seed array
        seed_index = (seed_index + 2) % 32;
    }

    random_numbers
}

fn vec_u16_to_string(vec: Vec<u16>) -> String {
    vec.iter()
       .map(|&num| num.to_string())
       .collect::<Vec<String>>()
       .join(" ")
}

