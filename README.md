# Secret Network Confidential Computation Layer (CCL)

A complete, compact, and simple encryption + RNG toolkit for EVM chains, written in TypeScript.

## Features

- Data encryption (key/value store) on EVM
- Generate on-chain verifiable randomness on EVM  
- Connected to [20+ EVM Chains](https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ethereum-evm-developer-toolkit/supported-networks)

## Installing

```bash
npm i secret-network-ccl
```

## Configure Environment Variables:

// your private EVM key

let privateKey = process.env.PRIVATE_KEY;

// your API endpoint

let endpoint = `https://sepolia.infura.io/v3/${process.env.API_KEY}`;

// the EVM chain that you want to use (see connected chains
[here](https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ethereum-evm-developer-toolkit/supported-networks))

let secretPathAddress = process.env.SECRET_NETWORK_ADDRESS

## Encrypting Data
```
const {encryptData} = require('./node_modules/secret-network-ccl')

let privateKey = "";
let endpoint = "https://sepolia.infura.io/v3/${process.env.API_KEY}";;
let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139";
let data = "I want to encrypt this data";
let password = "1234";

encryptData(privateKey, endpoint, secretPathAddress, data, password); 
```

## Querying Encrypted Data
```
const { SecretNetworkClient } = require("secretjs");

let query = async () => {
    const secretjs = new SecretNetworkClient({
      url: "https://lcd.testnet.secretsaturn.net",
      chainId: "pulsar-3",
    })
  
    const query_tx = await secretjs.query.compute.queryContract({
      contract_address:"secret1s79j3uaa0g49ncur884vv80ucz7hdwgltgke52",
      code_hash: "f0947ac3d0459bd5ccc24a43aa18762325f7582dc7919b4557ecf98b81345261",
      query: { retrieve_data: {password: "1234"} },
    })
    console.log(query_tx)
  }
  
  query()

```

## Requesting Randomness
```
// import the ccl package 
const {requestRandomness} = require('./node_modules/secret-network-ccl')

let privateKey = "";
let endpoint = "https://sepolia.infura.io/v3/${process.env.API_KEY}";;
let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139";
let numbers = "13"

requestRandomness(privateKey, endpoint, secretPathAddress, numbers); 


`numbers` must be a `String` of numbers between 1-65535 which will be returned as an `array` of `u16` 

// this returns

[12, 10, 4, 5, 3, 11, 9, 4, 5, 5, 11, 4, 1]
```

## Querying Randomness
```
const { SecretNetworkClient } = require("secretjs");

let query = async () => {
    const secretjs = new SecretNetworkClient({
      url: "https://lcd.testnet.secretsaturn.net",
      chainId: "pulsar-3",
    })
  
    const query_tx = await secretjs.query.compute.queryContract({
      contract_address:"secret10jgj4jduv82ua05aw948w6a26sq4zqqrs6ae7j",
      code_hash: "6f44e8cee8c1e6c536e3cfb5cb1264c14839100f46e0776f5c8eee7f07993569",
      query: { retrieve_random: {wallet: "0x49e01eb08bBF0696Ed0df8cD894906f7Da635929"} },
    })
    console.log(query_tx)
  }
  
  query()
```