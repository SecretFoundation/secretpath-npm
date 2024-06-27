# Secret Network Confidential Computation Layer (CCL)

A complete, compact, and simple encryption + RNG toolkit for EVM chains, written in TypeScript.

## Features

- Data encryption (key/value store) on EVM
- Generate on-chain verifiable randomness on EVM  
- Connected to [20+ EVM Chains](https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ethereum-evm-developer-toolkit/supported-networks)

## Secret Network Documentation
See Secret Network documentation for a complete [guide](https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ethereum-evm-developer-toolkit/secretpath-ccl-sdk)

## Installing

```bash
npm i secret-network-ccl
```

## Environment Configuration

Add EVM private key and API endpoint to your `.env` file:

PRIVATE_KEY=1987d98c566f622124850322fd3a064751bdabe20f50ca9fejfldf83720
INFURA_ENDPOINT=7bb38fdfdlfjldjf022734325edecdf0eS



## Encrypted Payloads

With `encryptData` you can encrypt a string in a Secret Network smart contract which can be queried with a password.

Select the EVM chain that you want to use to execute the Secret Network smart contract and update your `secretPathAddress` with the correct [gateway contract address](https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ethereum-evm-developer-toolkit/supported-networks/evm/evm-testnet/evm-testnet-gateway-contracts). For this example, we are using Sepolia:

```javascript
let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139";
```
`encryptData` requires `privateKey`, `endpoint`, `secretPathAddress`, `data`, and `password` parameters:

```javascript
const { encryptData } = require('secret-network-ccl');

let privateKey = process.env.PRIVATE_KEY;
let endpoint = `https://sepolia.infura.io/v3/${process.env.INFURA_ENDPOINT}`;
let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139";
let data = "I want to encrypt this data";
let password = "password";

encryptData(privateKey, endpoint, secretPathAddress, data, password);
```


## Verifiable Randomness

With `requestRandomness` you can request an array of up to 2000 random numbers on chain from Secret Network. 

Select the EVM chain that you want to use to execute the Secret Network smart contract and update your `secretPathAddress` with the correct [gateway contract address](https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ethereum-evm-developer-toolkit/supported-networks/evm/evm-testnet/evm-testnet-gateway-contracts). For this example, we are using Sepolia:

`let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139"`

`requestRandomness` requires `privateKey`, `endpoint`, `secretPathAddress`, `numbers`, and `max` parameters: 

`numbers` is the amount of numbers you want to request

`max` is the the max range the numbers can be. Ex: If you set `max` to 200, the largest random number that can be returned is 200.

```javascript
const {requestRandomness} = require('./node_modules/secret-network-ccl')

let privateKey = process.env.PRIVATE_KEY;
let endpoint = `https://sepolia.infura.io/v3/${process.env.INFURA_ENDPOINT}`;
let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139";
let numbers = "15";
let max = "5"; 

requestRandomness(privateKey, endpoint, secretPathAddress, numbers, max); 
```

## Executing Secret contracts

With `executeSecretContract` you can execute any SecretPath-compatible smart contract on Secret Network. 

Select the EVM chain that you want to use to execute the Secret Network smart contract and update your `secretPathAddress` with the correct [gateway contract address](https://docs.scrt.network/secret-network-documentation/confidential-computing-layer/ethereum-evm-developer-toolkit/supported-networks/evm/evm-testnet/evm-testnet-gateway-contracts). For this example, we are using Sepolia:

`let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139"`

For this example, we are going to execute the key value store contract on Secret Network.

`executeSecretContract` requires the Secret `contractAddress`, `codeHash`, `handle` (ie the function you want to execute in the Secret Network contract), and any parameters needed for the handle function, which in this case is `data` and `password`.

```javascript
const {executeSecretContract} = require('./node_modules/secret-network-ccl')
const dotenv = require('dotenv');
dotenv.config();

const contractAddress = "secret1s79j3uaa0g49ncur884vv80ucz7hdwgltgke52";
const contractCodeHash = "f0947ac3d0459bd5ccc24a43aa18762325f7582dc7919b4557ecf98b81345261";
let privateKey = process.env.PRIVATE_KEY;
let endpoint = `https://sepolia.infura.io/v3/${process.env.INFURA_ENDPOINT}`;
let secretPathAddress = "0x3879E146140b627a5C858a08e507B171D9E43139";
let data = { key: "data", value: "moonbeam" }
let password = { key: "password", value: "1234" };
let handle = "request_encrypt";

executeSecretContract( privateKey, endpoint, secretPathAddress, routing_contract, routing_code_hash, handle,  data,
  password); 
  ```
  
 ## Querying Secret contracts

With `querySecretContract` you can query any SecretPath-compatible smart contract on Secret Network. 

For this example, we are going to query the key value store contract on Secret Network.

`querySecretContract` requires the Secret `contractAddress`, `codeHash`, `handle` (ie the name of the query function you want to query in the Secret Network contract), and any parameters needed for the query, which in this case is `password`.

```javascript
const {querySecretContract} = require('./node_modules/secret-network-ccl')
const dotenv = require('dotenv');
dotenv.config();

const contractAddress = "secret1s79j3uaa0g49ncur884vv80ucz7hdwgltgke52";
const contractCodeHash = "f0947ac3d0459bd5ccc24a43aa18762325f7582dc7919b4557ecf98b81345261";
let password = { password: "2" }
let handle = "retrieve_data";

querySecretContract(  contractAddress, contractCodeHash, handle,
  password); 
  ```