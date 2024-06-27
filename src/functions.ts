const abi = require("../config/abi.js");
const { ethers } = require("ethers");
const {
  arrayify,
  hexlify,
  SigningKey,
  keccak256,
  recoverPublicKey,
  computeAddress
} = require("ethers/lib/utils");

const { SecretNetworkClient } = require("secretjs");

export async function loadESModules() {
  try {
    const neutrino = await import("@solar-republic/neutrino");
    const belt = await import("@blake.regalia/belt");
    return { neutrino, belt};
  } catch (error) {
    console.error("Failed to load ES modules:", error);
    return null;
  }
}

export async function requestRandomness(privateKey: string, endpoint: string, secretPathAddress: string, network: string, randomNumbers: string, max: string): Promise<void> {
  const modules = await loadESModules();
  if (!modules) {
    console.log("Required modules could not be loaded.");
    return;
  }

  const { ecdh, chacha20_poly1305_seal } = modules.neutrino;
  const {
    bytes,
    bytes_to_base64,
    json_to_bytes,
    sha256,
    concat,
    text_to_bytes,
    base64_to_bytes,
  } = modules.belt;

  let routing_contract;
  let routing_code_hash;
  let gatewayPublicKey;
  let destination_network;

  if (network === "testnet") {
    routing_contract = "secret1t5fktxrmkzkw4a44ssuyc84per4hc0jk93gwnd";
    routing_code_hash = "81b04bfb2ca756e135201152081a113e4c333648e7088558777a2743f382c566";
    gatewayPublicKey = "A20KrD7xDmkFXpNMqJn1CLpRaDLcdKpO1NdBBS7VpWh3";
    destination_network = "pulsar-3";
  } else if (network === "mainnet") {
    routing_contract = "secret159xu6qntmpka6gfl67yyply4wf9xd6m7s23p2h";
    routing_code_hash = "81b04bfb2ca756e135201152081a113e4c333648e7088558777a2743f382c566";
    gatewayPublicKey = "AqDWMqzQ0vXaAvw4XqMKjeq01WOdGoIaOlUmJa0PF1nQ";
    destination_network = "secret-4";
  } else {
    console.log("Invalid network parameter. Please use 'testnet' or 'mainnet'.");
    return;
  }

  const gatewayPublicKeyBytes = base64_to_bytes(gatewayPublicKey);

  const iface = new ethers.utils.Interface(abi);

  const provider = new ethers.providers.JsonRpcProvider(endpoint);
  const my_wallet = new ethers.Wallet(privateKey, provider);

  const myAddress = my_wallet.address;

  const wallet = ethers.Wallet.createRandom();
  const userPrivateKeyBytes = arrayify(wallet.privateKey);
  const userPublicKey = new SigningKey(wallet.privateKey).compressedPublicKey;
  const userPublicKeyBytes = arrayify(userPublicKey);

  const sharedKey = await sha256(ecdh(userPrivateKeyBytes, gatewayPublicKeyBytes));

  const callback_gas_limit = 300000;
  const handle = "request_random";

  const data = JSON.stringify({
    random_numbers: randomNumbers,
    wallet_address: myAddress,
    max: max
  });

  let publicClientAddress = secretPathAddress;

  const callbackAddress = publicClientAddress.toLowerCase();
  const callbackSelector = iface.getSighash(iface.getFunction("upgradeHandler"));
  const callbackGasLimit = Number(callback_gas_limit);

  const payload = {
    data: data,
    routing_info: routing_contract,
    routing_code_hash: routing_code_hash,
    user_address: myAddress,
    user_key: bytes_to_base64(userPublicKeyBytes),
    callback_address: bytes_to_base64(arrayify(callbackAddress)),
    callback_selector: bytes_to_base64(arrayify(callbackSelector)),
    callback_gas_limit: callbackGasLimit,
  };

  const payloadJson = JSON.stringify(payload);
  const plaintext = json_to_bytes(payload);

  const nonce = crypto.getRandomValues(bytes(12));

  const [ciphertextClient, tagClient] = chacha20_poly1305_seal(
    sharedKey,
    nonce,
    plaintext
  );
  const ciphertext = concat([ciphertextClient, tagClient]);

  const ciphertextHash = keccak256(ciphertext);

  const payloadHash = keccak256(
    concat([
      text_to_bytes("\x19Ethereum Signed Message:\n32"),
      arrayify(ciphertextHash),
    ])
  );

  const msgParams = ciphertextHash;
  const from = myAddress;
  const params = [from, msgParams];
  const method = "personal_sign";
  console.log(`Payload Hash: ${payloadHash}`);

  const messageArrayified = ethers.utils.arrayify(ciphertextHash);
  const payloadSignature = await my_wallet.signMessage(messageArrayified);
  console.log(`Payload Signature: ${payloadSignature}`);

  const user_pubkey = recoverPublicKey(payloadHash, payloadSignature);
  console.log(`Recovered public key: ${user_pubkey}`);
  console.log(
    `Verify this matches the user address: ${computeAddress(user_pubkey)}`
  );

  const _userAddress = myAddress;
  const _routingInfo = routing_contract;
  const _payloadHash = payloadHash;
  const _info = {
    user_key: hexlify(userPublicKeyBytes),
    user_pubkey: user_pubkey,
    routing_code_hash: routing_code_hash,
    task_destination_network: destination_network,
    handle: handle,
    nonce: hexlify(nonce),
    payload: hexlify(ciphertext),
    payload_signature: payloadSignature,
    callback_gas_limit: Number(callbackGasLimit),
  };

  console.log(`_userAddress: ${_userAddress}
  _routingInfo: ${_routingInfo} 
  _payloadHash: ${_payloadHash} 
  _info: ${JSON.stringify(_info)}
  _callbackAddress: ${callbackAddress},
  _callbackSelector: ${callbackSelector} ,
  _callbackGasLimit: ${callbackGasLimit}`);

  const functionData = iface.encodeFunctionData("send", [
    _payloadHash,
    _userAddress,
    _routingInfo,
    _info,
  ]);

  const gasFee = await provider.getGasPrice();
  const amountOfGas = gasFee.mul(callbackGasLimit).mul(3).div(2);

  const tx = {
    gasLimit: ethers.utils.hexlify(150000),
    to: publicClientAddress,
    value: ethers.utils.hexlify(amountOfGas),
    data: functionData,
  };

  try {
    const txResponse = await my_wallet.sendTransaction(tx);
    console.log(`Transaction sent! Hash: ${txResponse.hash}`);

    const receipt = await txResponse.wait();
    console.log(`Transaction confirmed! Block Number: ${receipt.blockNumber}`);
  } catch (error) {
    console.error(`Error sending transaction: ${error}`);
  }
}

  export async function encryptData(privateKey: string, endpoint: string, secretPathAddress: string, network: String, data_to_encypt: String, password: String ): Promise<void> {
    const modules = await loadESModules();
    if (!modules) {
      console.log("Required modules could not be loaded.");
      return;
    }
  
    const { ecdh, chacha20_poly1305_seal } = modules.neutrino;
    const {
      bytes,
      bytes_to_base64,
      json_to_bytes,
      sha256,
      concat,
      text_to_bytes,
      base64_to_bytes,
    } = modules.belt;
  
    let routing_contract;
    let routing_code_hash;
    let gatewayPublicKey;
    let destination_network;
  
    if (network === "testnet") {
      routing_contract = "secret1t5fktxrmkzkw4a44ssuyc84per4hc0jk93gwnd";
      routing_code_hash = "81b04bfb2ca756e135201152081a113e4c333648e7088558777a2743f382c566";
      gatewayPublicKey = "A20KrD7xDmkFXpNMqJn1CLpRaDLcdKpO1NdBBS7VpWh3";
      destination_network = "pulsar-3";
    } else if (network === "mainnet") {
      routing_contract = "secret159xu6qntmpka6gfl67yyply4wf9xd6m7s23p2h";
      routing_code_hash = "81b04bfb2ca756e135201152081a113e4c333648e7088558777a2743f382c566";
      gatewayPublicKey = "AqDWMqzQ0vXaAvw4XqMKjeq01WOdGoIaOlUmJa0PF1nQ";
      destination_network = "secret-4";
    } else {
      console.log("Invalid network parameter. Please use 'testnet' or 'mainnet'.");
      return;
    }
      const iface = new ethers.utils.Interface(abi);
  
      const provider = new ethers.providers.JsonRpcProvider(
       endpoint
      );
      // Create a wallet instance from a private key
      const my_wallet = new ethers.Wallet(privateKey, provider);
  
      const myAddress = my_wallet.address;
  
      // Generating ephemeral keys
    const wallet = ethers.Wallet.createRandom();
    const userPrivateKeyBytes = arrayify(wallet.privateKey);
    const userPublicKey = new SigningKey(wallet.privateKey).compressedPublicKey;
    const userPublicKeyBytes = arrayify(userPublicKey);
  
    // Gateway Encryption key for ChaCha20-Poly1305 Payload encryption
    const gatewayPublicKeyBytes = base64_to_bytes(gatewayPublicKey);
  
    // create the sharedKey via ECDH
    const sharedKey = await sha256(
      ecdh(userPrivateKeyBytes, gatewayPublicKeyBytes)
    );
  
    const callback_gas_limit = 300000;
  
    //the function name of the function that is called on the private contract
    const handle = "request_encrypt";
  
    const data = JSON.stringify({
     data: data_to_encypt,
      password: password,
    });
  
    let publicClientAddress = secretPathAddress; 
  
    const callbackAddress = publicClientAddress.toLowerCase();
    //This is an empty callback for the sake of having a callback in the sample code.
    //Here, you would put your callback selector for you contract in.
    const callbackSelector = iface.getSighash(
      iface.getFunction("upgradeHandler")
    );
    const callbackGasLimit = Number(callback_gas_limit);
  
    //payload data that are going to be encrypted
    const payload = {
      data: data,
      routing_info: routing_contract,
      routing_code_hash: routing_code_hash,
      user_address: myAddress,
      user_key: bytes_to_base64(userPublicKeyBytes),
      callback_address: bytes_to_base64(arrayify(callbackAddress)),
      callback_selector: bytes_to_base64(arrayify(callbackSelector)),
      callback_gas_limit: callbackGasLimit,
    };
  
    //build a Json of the payload
    const payloadJson = JSON.stringify(payload);
    const plaintext = json_to_bytes(payload);
  
    //generate a nonce for ChaCha20-Poly1305 encryption
    //DO NOT skip this, stream cipher encryptions are only secure with a random nonce!
    const nonce = crypto.getRandomValues(bytes(12));
  
    //Encrypt the payload using ChachaPoly1305 and concat the ciphertext+tag to fit the Rust ChaChaPoly1305 requirements
    const [ciphertextClient, tagClient] = chacha20_poly1305_seal(
      sharedKey,
      nonce,
      plaintext
    );
    const ciphertext = concat([ciphertextClient, tagClient]);
  
    //get Metamask to sign the payloadhash with personal_sign
    const ciphertextHash = keccak256(ciphertext);
  
    //this is what metamask really signs with personal_sign, it prepends the ethereum signed message here
    const payloadHash = keccak256(
      concat([
        text_to_bytes("\x19Ethereum Signed Message:\n32"),
        arrayify(ciphertextHash),
      ])
    );
  
    //this is what we provide to metamask
    const msgParams = ciphertextHash;
    const from = myAddress;
    const params = [from, msgParams];
    const method = "personal_sign";
    console.log(`Payload Hash: ${payloadHash}`);
  
    const messageArrayified = ethers.utils.arrayify(ciphertextHash); // Convert the hash to a Uint8Array
    const payloadSignature = await my_wallet.signMessage(messageArrayified); // Sign the message directly with the wallet
    console.log(`Payload Signature: ${payloadSignature}`);
  
    // Continue with the rest of your original code for public key recovery and address computation
    const user_pubkey = recoverPublicKey(payloadHash, payloadSignature);
    console.log(`Recovered public key: ${user_pubkey}`);
    console.log(
      `Verify this matches the user address: ${computeAddress(user_pubkey)}`
    );
  
    // function data to be abi encoded
    const _userAddress = myAddress;
    const _routingInfo = routing_contract;
    const _payloadHash = payloadHash;
    const _info = {
      user_key: hexlify(userPublicKeyBytes),
      user_pubkey: user_pubkey,
      routing_code_hash: routing_code_hash,
      task_destination_network: destination_network, //Destination for the task, here: pulsar-3 testnet
      handle: handle,
      nonce: hexlify(nonce),
      payload: hexlify(ciphertext),
      payload_signature: payloadSignature,
      callback_gas_limit: Number(callbackGasLimit),
    };
  
    console.log(`_userAddress: ${_userAddress}
    _routingInfo: ${_routingInfo} 
    _payloadHash: ${_payloadHash} 
    _info: ${JSON.stringify(_info)}
    _callbackAddress: ${callbackAddress},
    _callbackSelector: ${callbackSelector} ,
    _callbackGasLimit: ${callbackGasLimit}`);
  
    const functionData = iface.encodeFunctionData("send", [
      _payloadHash,
      _userAddress,
      _routingInfo,
      _info,
    ]);
  
    const gasFee = await provider.getGasPrice();
    const amountOfGas = gasFee.mul(callbackGasLimit).mul(3).div(2);
  
    // Define the transaction object
    const tx = {
      gasLimit: ethers.utils.hexlify(150000), // Use hexlify to ensure the gas limit is correctly formatted
      to: publicClientAddress,
      // from: myAddress, // This is not needed because the wallet knows the 'from' address
      value: ethers.utils.hexlify(amountOfGas), // Make sure to hexlify the amount
      data: functionData,
    };
  
    // Send the transaction using the wallet's sendTransaction method
    try {
      const txResponse = await my_wallet.sendTransaction(tx);
      console.log(`Transaction sent! Hash: ${txResponse.hash}`);
  
      // Wait for the transaction to be mined
      const receipt = await txResponse.wait();
      console.log(`Transaction confirmed! Block Number: ${receipt.blockNumber}`);
    } catch (error) {
      console.error(`Error sending transaction: ${error}`);
    }
  
    }

    export async function executeSecretContract(
      privateKey: string, 
      endpoint: string, 
      secretPathAddress: string, 
      contractAddress: string, 
      codeHash: string, 
      network: string,
      executeHandle: string,
      ...strings: { key: string, value: string }[]
    ): Promise<void> {
      const modules = await loadESModules();
      if (!modules) {
        console.log("Required modules could not be loaded.");
        return;
      }
    
      const { ecdh, chacha20_poly1305_seal } = modules.neutrino;
      const {
        bytes,
        bytes_to_base64,
        json_to_bytes,
        sha256,
        concat,
        text_to_bytes,
        base64_to_bytes,
      } = modules.belt;

    let gatewayPublicKey;
    let destination_network;
  
    if (network === "testnet") {

      gatewayPublicKey = "A20KrD7xDmkFXpNMqJn1CLpRaDLcdKpO1NdBBS7VpWh3";
      destination_network = "pulsar-3";
    } else if (network === "mainnet") {

      gatewayPublicKey = "AqDWMqzQ0vXaAvw4XqMKjeq01WOdGoIaOlUmJa0PF1nQ";
      destination_network = "secret-4";
    } else {
      console.log("Invalid network parameter. Please use 'testnet' or 'mainnet'.");
      return;
    }
    
      const routing_contract = contractAddress;
      const routing_code_hash = codeHash;
      const iface = new ethers.utils.Interface(abi);
    
      const provider = new ethers.providers.JsonRpcProvider(endpoint);
      const my_wallet = new ethers.Wallet(privateKey, provider);
      const myAddress = my_wallet.address;
    
      // Generating ephemeral keys
      const wallet = ethers.Wallet.createRandom();
      const userPrivateKeyBytes = arrayify(wallet.privateKey);
      const userPublicKey = new SigningKey(wallet.privateKey).compressedPublicKey;
      const userPublicKeyBytes = arrayify(userPublicKey);
    
      // Gateway Encryption key for ChaCha20-Poly1305 Payload encryption
      const gatewayPublicKeyBytes = base64_to_bytes(gatewayPublicKey);
    
      // create the sharedKey via ECDH
      const sharedKey = await sha256(
        ecdh(userPrivateKeyBytes, gatewayPublicKeyBytes)
      );
    
      const callback_gas_limit = 300000;
    
      // the function name of the function that is called on the private contract
      const handle = executeHandle; 
    
      // Building the data object dynamically
      const data: { [key: string]: string } = {};
      strings.forEach(string => {
        if (string) data[string.key] = string.value;
      });
    
      const jsonData = JSON.stringify(data);
    
      let publicClientAddress = secretPathAddress; 
      const callbackAddress = publicClientAddress.toLowerCase();
      const callbackSelector = iface.getSighash(iface.getFunction("upgradeHandler"));
      const callbackGasLimit = Number(callback_gas_limit);
    
      const payload = {
        data: jsonData,
        routing_info: routing_contract,
        routing_code_hash: routing_code_hash,
        user_address: myAddress,
        user_key: bytes_to_base64(userPublicKeyBytes),
        callback_address: bytes_to_base64(arrayify(callbackAddress)),
        callback_selector: bytes_to_base64(arrayify(callbackSelector)),
        callback_gas_limit: callbackGasLimit,
      };
    
      const payloadJson = JSON.stringify(payload);
      const plaintext = json_to_bytes(payload);
    
      const nonce = crypto.getRandomValues(bytes(12));
    
      const [ciphertextClient, tagClient] = chacha20_poly1305_seal(
        sharedKey,
        nonce,
        plaintext
      );
      const ciphertext = concat([ciphertextClient, tagClient]);
    
      const ciphertextHash = keccak256(ciphertext);
    
      const payloadHash = keccak256(
        concat([
          text_to_bytes("\x19Ethereum Signed Message:\n32"),
          arrayify(ciphertextHash),
        ])
      );
    
      const msgParams = ciphertextHash;
      const from = myAddress;
      const params = [from, msgParams];
      const method = "personal_sign";
      console.log(`Payload Hash: ${payloadHash}`);
    
      const messageArrayified = ethers.utils.arrayify(ciphertextHash);
      const payloadSignature = await my_wallet.signMessage(messageArrayified);
      console.log(`Payload Signature: ${payloadSignature}`);
    
      const user_pubkey = recoverPublicKey(payloadHash, payloadSignature);
      console.log(`Recovered public key: ${user_pubkey}`);
      console.log(
        `Verify this matches the user address: ${computeAddress(user_pubkey)}`
      );
    
      const _userAddress = myAddress;
      const _routingInfo = routing_contract;
      const _payloadHash = payloadHash;
      const _info = {
        user_key: hexlify(userPublicKeyBytes),
        user_pubkey: user_pubkey,
        routing_code_hash: routing_code_hash,
        task_destination_network: destination_network,
        handle: handle,
        nonce: hexlify(nonce),
        payload: hexlify(ciphertext),
        payload_signature: payloadSignature,
        callback_gas_limit: Number(callbackGasLimit),
      };
    
      console.log(`_userAddress: ${_userAddress}
      _routingInfo: ${_routingInfo} 
      _payloadHash: ${_payloadHash} 
      _info: ${JSON.stringify(_info)}
      _callbackAddress: ${callbackAddress},
      _callbackSelector: ${callbackSelector} ,
      _callbackGasLimit: ${callbackGasLimit}`);
    
      const functionData = iface.encodeFunctionData("send", [
        _payloadHash,
        _userAddress,
        _routingInfo,
        _info,
      ]);
    
      const gasFee = await provider.getGasPrice();
      const amountOfGas = gasFee.mul(callbackGasLimit).mul(3).div(2);
    
      const tx = {
        gasLimit: ethers.utils.hexlify(150000),
        to: publicClientAddress,
        value: ethers.utils.hexlify(amountOfGas),
        data: functionData,
      };
    
      try {
        const txResponse = await my_wallet.sendTransaction(tx);
        console.log(`Transaction sent! Hash: ${txResponse.hash}`);
    
        const receipt = await txResponse.wait();
        console.log(`Transaction confirmed! Block Number: ${receipt.blockNumber}`);
      } catch (error) {
        console.error(`Error sending transaction: ${error}`);
      }
    }
    
    
  export async function queryRandomness(wallet: string, network: string): Promise<void> {

    let chainId;
    let url; 
    let contractAddress;
    let contractCodeHash; 
  
    if (network === "testnet") {

      chainId = "pulsar-3";
      url = "https://lcd.testnet.secretsaturn.net";
      contractAddress = "secret1t5fktxrmkzkw4a44ssuyc84per4hc0jk93gwnd"; 
      contractCodeHash = "81b04bfb2ca756e135201152081a113e4c333648e7088558777a2743f382c566";
    } else if (network === "mainnet") {

      chainId = "secret-4";
      url = "https://lcd.mainnet.secretsaturn.net";
      contractAddress = "secret159xu6qntmpka6gfl67yyply4wf9xd6m7s23p2h"; 
      contractCodeHash = "81b04bfb2ca756e135201152081a113e4c333648e7088558777a2743f382c566";
    } else {
      console.log("Invalid network parameter. Please use 'testnet' or 'mainnet'.");
      return;
    }

    const secretjs = new SecretNetworkClient({
      url: url,
      chainId: chainId
    })
  
    const query_tx = await secretjs.query.compute.queryContract({
      contract_address: contractAddress,
      code_hash:  contractCodeHash,
      query: { retrieve_random: {wallet} },
    })
    console.log(query_tx)
  };

  export async function querySecretContract(
    contractAddress: string, 
    codeHash: string, 
    network: string,
    queryName: string, 
    queryParameters?: { [key: string]: string | number }
  ): Promise<void> {
    let chainId;
    let url; 

  
    if (network === "testnet") {

      chainId = "pulsar-3";
      url = "https://lcd.testnet.secretsaturn.net";

    } else if (network === "mainnet") {

      chainId = "secret-4";
      url = "https://lcd.mainnet.secretsaturn.net";

    } else {
      console.log("Invalid network parameter. Please use 'testnet' or 'mainnet'.");
      return;
    }


    const secretjs = new SecretNetworkClient({
      url: url,
      chainId: chainId
    })
  
    // Building the dynamic query object
    const query: any = { [queryName]: {} };
  
    // Adding optional parameters to the query
    if (queryParameters) {
      for (const [key, value] of Object.entries(queryParameters)) {
        query[queryName][key] = value;
      }
    }
  
    const query_tx = await secretjs.query.compute.queryContract({
      contract_address: contractAddress,
      code_hash: codeHash,
      query: query,
    });
    console.log(query_tx);
  }
  