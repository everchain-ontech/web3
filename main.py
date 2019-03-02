import json
import time

from web3 import Web3, HTTPProvider

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
    con_signtx = web3.thk.signTransaction(con_tx, privarte_key)
    contract_hash = web3.thk.sendRawTx(con_signtx)
    # 获取合约hash
    time.sleep(5)
    conresp = web3.thk.getTransactionByHash("2", contract_hash["TXhash"])
    contract_address = conresp['contractAddress']
    web3.thk.saveContract(contract_address, contractresp)
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

    cotractName = "SimpleStorage"
    contractText = "pragma solidity >= 0.4.0;contract " + cotractName + "{uint storedData; function set(uint x) " \
                                                                        "public { storedData = x;} function get() " \
                                                                        "public view returns (uint) { return " \
                                                                        "storedData;}} "
    Transfer()
    thk = web3.thk
    contractAddress = ReleaseContract(cotractName, contractText)
    print(contractAddress)
    getcontract = thk.getContract(contractAddress)
    mycon = thk.contract(address=contractAddress, abi=getcontract[cotractName]["info"]["abiDefinition"])
    accountInfo = thk.getAccount(address)

    txn = mycon.functions.set(2).buildTx({
        "chainId": "2",
        "from": address,
        "nonce": str(accountInfo["nonce"])
    })
    print(txn)
    privartekey = get_privatekey()
    con_sign_tx = thk.signTransaction(txn, privartekey)
    contracthash = thk.sendRawTx(con_sign_tx)

    time.sleep(5)
    accountInfo = thk.getAccount(address)
    gettxn = mycon.functions.get().buildTx({
        "chainId": "2",
        "from": address,
        "nonce": str(accountInfo["nonce"])
    })
    privartekey = get_privatekey()
    con_sign_tx = thk.signTransaction(gettxn, privartekey)
    contracthash = thk.sendRawTx(con_sign_tx)
    print(accountInfo)
