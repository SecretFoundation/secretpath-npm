import { SecretNetworkClient, Wallet, coinsFromString } from "secretjs"
import * as fs from "fs"
import dotenv from "dotenv"
dotenv.config()

const wallet = new Wallet(process.env.MNEMONIC)

const contract_wasm = fs.readFileSync("../contract.wasm.gz")

//mainnet
const gatewayAddress = "secret1qzk574v8lckjmqdg3r3qf3337pk45m7qd8x02a";

//testnet
// const gatewayAddress = "secret10ex7r7c4y704xyu086lf74ymhrqhypayfk7fkj"

//mainnet
const gatewayHash = "012dd8efab9526dec294b6898c812ef6f6ad853e32172788f54ef3c305c1ecc5";

//testneet
// const gatewayHash = "012dd8efab9526dec294b6898c812ef6f6ad853e32172788f54ef3c305c1ecc5"

//mainnet
const gatewayPublicKey = "0x04a0d632acd0d2f5da02fc385ea30a8deab4d5639d1a821a3a552625ad0f1759d0d2e80ca3adb236d90caf1b12e0ddf3a351c5729b5e00505472dca6fed5c31e2a";

//testnet
// const gatewayPublicKey = "0x046d0aac3ef10e69055e934ca899f508ba516832dc74aa4ed4d741052ed5a568774d99d3bfed641a7935ae73aac8e34938db747c2f0e8b2aa95c25d069a575cc8b"

const gatewayPublicKeyBytes = Buffer.from(gatewayPublicKey.substring(2), "hex").toString("base64")

//mainnet
const secretjs = new SecretNetworkClient({
  chainId: "secret-4",
  url: "https://lcd.mainnet.secretsaturn.net",
  wallet: wallet,
  walletAddress: wallet.address,
})


//testnet
// const secretjs = new SecretNetworkClient({
//   chainId: "pulsar-3",
//   url: "https://api.pulsar3.scrttestnet.com",
//   wallet: wallet,
//   walletAddress: wallet.address,
// })

// Declare global variables
let codeId
let contractCodeHash
let contractAddress

let upload_contract = async () => {
  console.log("Starting deployment…")

  let tx = await secretjs.tx.compute.storeCode(
    {
      sender: wallet.address,
      wasm_byte_code: contract_wasm,
      source: "",
      builder: "",
    },
    {
      gasLimit: 4_000_000,
    },
  )

  codeId = Number(tx.arrayLog.find((log) => log.type === "message" && log.key === "code_id").value)
  console.log("codeId: ", codeId)

  contractCodeHash = (await secretjs.query.compute.codeHashByCodeId({ code_id: codeId })).code_hash
  console.log(`Contract hash: ${contractCodeHash}`)
}

let instantiate_contract = async () => {
  // if (!codeId || !contractCodeHash) {
  //   throw new Error("codeId or contractCodeHash is not set.")
  // }
  // console.log("Instantiating contract…")

  let init = {
    gateway_address: gatewayAddress,
    gateway_hash: gatewayHash,
    gateway_key: gatewayPublicKeyBytes,
  }
  let tx = await secretjs.tx.compute.instantiateContract(
    {
      code_id: 1725,
      sender: wallet.address,
      code_hash: "81b04bfb2ca756e135201152081a113e4c333648e7088558777a2743f382c566",
      init_msg: init,
      label: "SecretPath RNG " + Math.ceil(Math.random() * 10000),
    },
    {
      gasLimit: 4_000_000,
    })
  // )

  // //Find the contract_address in the logs
  // const contractAddress = tx.arrayLog.find((log) => log.type === "message" && log.key === "contract_address").value

  // console.log("contract address: ", contractAddress)

  console.log(tx)
}

instantiate_contract()

// // Chain the execution using promises
// upload_contract()
//   .then(() => {
//     instantiate_contract()
//   })
//   .catch((error) => {
//     console.error("Error:", error)
//   })
