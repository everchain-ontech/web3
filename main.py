import json
import time

from web3 import Web3, HTTPProvider

from web3._utils.encoding import (
    remove_0x_prefix
)

address = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"


def Transfer():
    """转账"""
    account_info = web3.thk.getAccount(address)
    con_tx = {
        "chainId": "2",
        "from": address,
        "nonce": str(account_info["nonce"]),
        "to": "0x0000000000000000000000000000000000000000",
        "input": '',
        "value": "1111111110"
    }
    privarte_key = get_privatekey()
    print("privarte_key:" + str(privarte_key))
    con_sign_tx = web3.thk.signTransaction(con_tx, privarte_key)
    contracthash = web3.thk.sendRawTx(con_sign_tx)
    # 获取合约hash
    time.sleep(5)
    conresp = web3.thk.getTxByHash("2", contracthash["TXhash"])
    return conresp['contractAddress']


def ReleaseContract(contractName, contract_text):
    account_info = web3.thk.getAccount(address)
    contractresp = web3.thk.compileContract("2", contract_text)
    code = contractresp[contractName]["code"]
    # 发布合约
    con_tx = {
        "chainId": "2",
        "from": address,
        "nonce": str(account_info["nonce"]),
        "to": "",
        "input": code,
        "value": "0"
    }
    privarte_key = get_privatekey()
    print(privarte_key)
    con_signtx = web3.thk.signTransaction(con_tx, privarte_key)
    contract_hash = web3.thk.sendRawTx(con_signtx)
    # 获取合约hash
    time.sleep(5)
    conresp = web3.thk.getTxByHash("2", contract_hash["TXhash"])
    contract_address = conresp['contractAddress']
    res = web3.thk.saveContract(contract_address, contractresp)
    return contract_address


def get_privatekey():
    key = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
    ret = web3.eth.account.encrypt(key, "123456")

    print("keyFile", ret)
    # # 打开一个文件
    keyfile = open("./keystore/key1", "w")
    keyfile.write(json.dumps(ret))
    #
    # # 关闭打开的文件
    keyfile.close()

    with open("./keystore/key1") as keyfile:
        encrypted_key = keyfile.read()

        encrypted_keyobj = json.loads(encrypted_key)
        print("encrypted_keyobj", encrypted_keyobj)
        private_key = web3.eth.account.decrypt(encrypted_keyobj, '123456')

    return private_key


if __name__ == "__main__":
    FULL_NODE_HOSTS = 'http://thinkey.natapp1.cc/http2rpc'
    provider = HTTPProvider(FULL_NODE_HOSTS)
    web3 = Web3(provider)

    cotractName = "Greeter"
    contractText = '''
    pragma solidity >=0.4.21;

contract Greeter {
    string public greeting;

    constructor() public  {
        greeting = 'Hello';
    }

    function setGreeting(string memory _greeting) public  {
        greeting = _greeting;
    }

    function greet() view public  returns ( string memory)  {
        return greeting;
    }
}
    '''
    privartekey = get_privatekey()
    # 初始化私钥
    web3.thk.defaultPrivateKey = privartekey

    # 初始化账户地址
    web3.thk.defaultAddress = address
    # 测试发送一笔交易
    Transfer()

    # 测试发布合约
    contractAddress = ReleaseContract(cotractName, contractText)
    print(contractAddress)
    getcontract = web3.thk.getContract(contractAddress)
    abi = getcontract[cotractName]["info"]["abiDefinition"]
    contract_bin = remove_0x_prefix(getcontract[cotractName]["code"])
    Greeter = web3.thk.contract(abi=abi, bytecode=contract_bin)

    # 构造函数
    tx_hash = Greeter.constructor().transact()
    # 等待交易执行完成
    tx_receipt = web3.thk.waitForTransactionReceipt("2", tx_hash["TXhash"])

    # 初始化合约对象
    greeter = web3.thk.contract(
        address=tx_receipt['contractAddress'],
        abi=abi,
    )

    account_info = web3.thk.getAccount(address)
    # 执行合约内函数
    txn = greeter.functions.setGreeting("asd").buildTx({
        "chainId": "2",
        "from": address,
        "nonce": str(account_info["nonce"])
    })
    con_sign_tx = web3.thk.signTransaction(txn, web3.thk.defaultPrivateKey)
    contracthash = web3.thk.sendRawTx(con_sign_tx)
    time.sleep(5)
    account_info = web3.thk.getAccount(address)

    gettxn = greeter.functions.greet().buildTx({
        "chainId": "2",
        "from": address,
        "nonce": str(account_info["nonce"])
    })
    con_sign_tx = web3.thk.signTransaction(gettxn, web3.thk.defaultPrivateKey)
    result = web3.thk.callRawTx(con_sign_tx)

    print(result)
