from eth_account import (
    Account,
)

from collections import (
    Mapping,
)

from eth_keys import (
    keys
)

from eth_utils import (
    apply_to_return_value,
    is_checksum_address,
    keccak as eth_utils_keccak,
    is_string,
)
from hexbytes import (
    HexBytes,
)

from web3._utils.blocks import (
    select_method_for_block_identifier,
)
from web3._utils.decorators import (
    deprecated_for,
)
from web3._utils.empty import (
    empty,
)
from web3._utils.encoding import (
    to_hex,
    to_bytes,
    remove_0x_prefix
)

from web3._utils.filters import (
    BlockFilter,
    LogFilter,
    TransactionFilter,
)
from web3._utils.threads import (
    Timeout,
)
from web3._utils.toolz import (
    assoc,
    merge,
)
from web3._utils.transactions import (
    assert_valid_transaction_params,
    extract_valid_transaction_params,
    get_buffered_gas_estimate,
    get_required_transaction,
    replace_transaction,
    wait_for_transaction_receipt,
)
from web3.contract import (
    Contract,
)
from web3.exceptions import (
    TimeExhausted,
)
from web3.iban import (
    Iban,
)
from web3.module import (
    Module,
)


class Thk(Module):
    account = Account()
    defaultAccount = empty
    defaultBlock = "latest"
    defaultContractFactory = Contract
    iban = Iban
    gasPriceStrategy = None

    @deprecated_for("doing nothing at all")
    def enable_unaudited_features(self):
        pass

    def namereg(self):
        raise NotImplementedError()

    def icapNamereg(self):
        raise NotImplementedError()

    @property
    def protocolVersion(self):
        return self.web3.manager.request_blocking("eth_protocolVersion", [])

    @property
    def syncing(self):
        return self.web3.manager.request_blocking("eth_syncing", [])

    @property
    def coinbase(self):
        return self.web3.manager.request_blocking("eth_coinbase", [])

    @property
    def mining(self):
        return self.web3.manager.request_blocking("eth_mining", [])

    @property
    def hashrate(self):
        return self.web3.manager.request_blocking("eth_hashrate", [])

    @property
    def gasPrice(self):
        return self.web3.manager.request_blocking("eth_gasPrice", [])

    @property
    def accounts(self):
        return self.web3.manager.request_blocking("eth_accounts", [])

    @property
    def blockNumber(self):
        return self.web3.manager.request_blocking("eth_blockNumber", [])

    # ddd
    def getAccount(self, account, block_identifier=None):
        if block_identifier is None:
            block_identifier = self.defaultBlock
        return self.web3.manager.request_blocking(
            "GetAccount",
            {
                "chainId": "1",
                "address": account
            }
        )

    # ddd
    def compileContract(self, chainId, contractText):
        return self.web3.manager.request_blocking(
            "CompileContract",
            {
                "chainId": chainId,
                "contract": contractText
            }
        )

    def getStorageAt(self, account, position, block_identifier=None):
        if block_identifier is None:
            block_identifier = self.defaultBlock
        return self.web3.manager.request_blocking(
            "eth_getStorageAt",
            [account, position, block_identifier]
        )

    def getCode(self, account, block_identifier=None):
        if block_identifier is None:
            block_identifier = self.defaultBlock
        return self.web3.manager.request_blocking(
            "eth_getCode",
            [account, block_identifier],
        )

    def getBlock(self, block_identifier, full_transactions=False):
        """
        `eth_getBlockByHash`
        `eth_getBlockByNumber`
        """
        method = select_method_for_block_identifier(
            block_identifier,
            if_predefined='eth_getBlockByNumber',
            if_hash='eth_getBlockByHash',
            if_number='eth_getBlockByNumber',
        )

        return self.web3.manager.request_blocking(
            method,
            [block_identifier, full_transactions],
        )

    def getBlockTransactionCount(self, block_identifier):
        """
        `eth_getBlockTransactionCountByHash`
        `eth_getBlockTransactionCountByNumber`
        """
        method = select_method_for_block_identifier(
            block_identifier,
            if_predefined='eth_getBlockTransactionCountByNumber',
            if_hash='eth_getBlockTransactionCountByHash',
            if_number='eth_getBlockTransactionCountByNumber',
        )
        return self.web3.manager.request_blocking(
            method,
            [block_identifier],
        )

    def getUncleCount(self, block_identifier):
        """
        `eth_getUncleCountByBlockHash`
        `eth_getUncleCountByBlockNumber`
        """
        method = select_method_for_block_identifier(
            block_identifier,
            if_predefined='eth_getUncleCountByBlockNumber',
            if_hash='eth_getUncleCountByBlockHash',
            if_number='eth_getUncleCountByBlockNumber',
        )
        return self.web3.manager.request_blocking(
            method,
            [block_identifier],
        )

    def getUncleByBlock(self, block_identifier, uncle_index):
        """
        `eth_getUncleByBlockHashAndIndex`
        `eth_getUncleByBlockNumberAndIndex`
        """
        method = select_method_for_block_identifier(
            block_identifier,
            if_predefined='eth_getUncleByBlockNumberAndIndex',
            if_hash='eth_getUncleByBlockHashAndIndex',
            if_number='eth_getUncleByBlockNumberAndIndex',
        )
        return self.web3.manager.request_blocking(
            method,
            [block_identifier, uncle_index],
        )

    def getTransaction(self, transaction_hash):
        return self.web3.manager.request_blocking(
            "eth_getTransactionByHash",
            [transaction_hash],
        )

    @deprecated_for("w3.eth.getTransactionByBlock")
    def getTransactionFromBlock(self, block_identifier, transaction_index):
        """
        Alias for the method getTransactionByBlock
        Depreceated to maintain naming consistency with the json-rpc API
        """
        return self.getTransactionByBlock(block_identifier, transaction_index)

    def getTransactionByBlock(self, block_identifier, transaction_index):
        """
        `eth_getTransactionByBlockHashAndIndex`
        `eth_getTransactionByBlockNumberAndIndex`
        """
        method = select_method_for_block_identifier(
            block_identifier,
            if_predefined='eth_getTransactionByBlockNumberAndIndex',
            if_hash='eth_getTransactionByBlockHashAndIndex',
            if_number='eth_getTransactionByBlockNumberAndIndex',
        )
        return self.web3.manager.request_blocking(
            method,
            [block_identifier, transaction_index],
        )

    def waitForTransactionReceipt(self, transaction_hash, timeout=120):
        try:
            return wait_for_transaction_receipt(self.web3, transaction_hash, timeout)
        except Timeout:
            raise TimeExhausted(
                "Transaction {} is not in the chain, after {} seconds".format(
                    transaction_hash,
                    timeout,
                )
            )

    def getTransactionReceipt(self, transaction_hash):
        return self.web3.manager.request_blocking(
            "eth_getTransactionReceipt",
            [transaction_hash],
        )

    def getTransactionCount(self, account, block_identifier=None):
        if block_identifier is None:
            block_identifier = self.defaultBlock
        return self.web3.manager.request_blocking(
            "eth_getTransactionCount",
            [
                account,
                block_identifier,
            ],
        )

    def replaceTransaction(self, transaction_hash, new_transaction):
        current_transaction = get_required_transaction(self.web3, transaction_hash)
        return replace_transaction(self.web3, current_transaction, new_transaction)

    def modifyTransaction(self, transaction_hash, **transaction_params):
        assert_valid_transaction_params(transaction_params)
        current_transaction = get_required_transaction(self.web3, transaction_hash)
        current_transaction_params = extract_valid_transaction_params(current_transaction)
        new_transaction = merge(current_transaction_params, transaction_params)
        return replace_transaction(self.web3, current_transaction, new_transaction)

    # ddd
    def sendTx(self, chainId, fromAddr, toAddr, nonce, value, input):
        # TODO: move to middleware
        # if 'from' not in transaction and is_checksum_address(self.defaultAccount):
        #     transaction = assoc(transaction, 'from', self.defaultAccount)

        # TODO: move gas estimation in middleware
        # if 'gas' not in transaction:
        #     transaction = assoc(
        #         transaction,
        #         'gas',
        #         get_buffered_gas_estimate(self.web3, transaction),
        #     )

        return self.web3.manager.request_blocking(
            "SendTx",
            {
                "chainId": chainId,
                "from": fromAddr,
                "to": toAddr,
                "nonce": nonce,
                "value": value,
                "input": input
            }
        )

    # ddd
    def getBlockTxs(self, chainId, height, page, size):
        return self.web3.manager.request_blocking(
            "GetBlockTxs",
            {
                "chainId": chainId,
                "height": height,
                "page": page,
                "size": size
            }
        )

    # ddd
    def getStats(self, chainId):
        return self.web3.manager.request_blocking(
            "GetStats",
            {
                "chainId": chainId
            }
        )

    # ddd
    def getTransactions(self, address, startHeight, endHeight):
        return self.web3.manager.request_blocking(
            "GetTransactions",
            {
                "address": address,
                "startHeight": startHeight,
                "endHeight": endHeight
            }
        )

    # ddd
    def getTransactionByHash(self, chainId, hash):
        return self.web3.manager.request_blocking(
            "GetTransactionByHash",
            {
                "chainId": chainId,
                "hash": hash
            }
        )

    # ddd
    def callTransaction(self, chainId, fromAddr, toAddr, nonce, value, input):
        return self.web3.manager.request_blocking(
            "CallTransaction",
            {
                "chainId": chainId,
                "from": fromAddr,
                "to": toAddr,
                "nonce": nonce,
                "value": value,
                "input": input
            }
        )

    # ddd
    def getBlockHeader(self, chainId, height):
        return self.web3.manager.request_blocking(
            "GetBlockHeader",
            {
                "chainId": chainId, "height": height
            }
        )

    # ddd
    def saveContract(self, address, contract):
        return self.web3.manager.request_blocking(
            "SaveContract",
            {
                "contractaddr": address,
                "contract": contract
            }
        )

    # ddd
    def getContract(self, address):
        return self.web3.manager.request_blocking(
            "GetContract",
            {
                "contractaddr": address
            }
        )

    def sendRawTx(self, transaction):
        return self.web3.manager.request_blocking(
            "SendTx", transaction
        )

    def sendRawTransaction(self, raw_transaction):
        return self.web3.manager.request_blocking(
            "eth_sendRawTransaction",
            [raw_transaction],
        )

    def sign(self, account, data=None, hexstr=None, text=None):
        message_hex = to_hex(data, hexstr=hexstr, text=text)
        return self.web3.manager.request_blocking(
            "eth_sign", [account, message_hex],
        )

    def signTransaction(self, transaction_dict, private_key):
        if not isinstance(transaction_dict, Mapping):
            raise TypeError("transaction_dict must be dict-like, got %r" % transaction_dict)
        # account = self.privateKeyToAccount(private_key)
        #
        # if 'from' in transaction_dict:
        #     if transaction_dict['from'] == account.address:
        #         sanitized_transaction = dissoc(transaction_dict, 'from')
        #     else:
        #         raise TypeError("from field must match key's %s, but it was %s" % (
        #             account.address,
        #             transaction_dict['from'],
        #         ))
        # else:
        #     sanitized_transaction = transaction_dict
        sign_str = transaction_dict["chainId"] + remove_0x_prefix(transaction_dict["from"]) + \
                   remove_0x_prefix(transaction_dict["to"]) + transaction_dict["nonce"] + \
                   transaction_dict["value"] + remove_0x_prefix(transaction_dict["input"])
        sign_bytes = to_bytes(text=sign_str)
        res = eth_utils_keccak(sign_bytes)
        print(to_hex(res))
        sign_hash = self.account.signHash(to_hex(res), private_key=private_key)
        transaction_dict["sig"] = to_hex(sign_hash.signature)
        pk = keys.PrivateKey(private_key)
        transaction_dict["pub"] = "0x04" + pk.public_key.to_hex()[2:]
        return transaction_dict

    @apply_to_return_value(HexBytes)
    def call(self, transaction, block_identifier=None):
        # TODO: move to middleware
        if 'from' not in transaction and is_checksum_address(self.defaultAccount):
            transaction = assoc(transaction, 'from', self.defaultAccount)

        # TODO: move to middleware
        if block_identifier is None:
            block_identifier = self.defaultBlock
        return self.web3.manager.request_blocking(
            "eth_call",
            [transaction, block_identifier],
        )

    def estimateGas(self, transaction, block_identifier=None):
        # TODO: move to middleware
        if 'from' not in transaction and is_checksum_address(self.defaultAccount):
            transaction = assoc(transaction, 'from', self.defaultAccount)

        if block_identifier is None:
            params = [transaction]
        else:
            params = [transaction, block_identifier]

        return self.web3.manager.request_blocking(
            "eth_estimateGas",
            params,
        )

    def filter(self, filter_params=None, filter_id=None):
        if filter_id and filter_params:
            raise TypeError(
                "Ambiguous invocation: provide either a `filter_params` or a `filter_id` argument. "
                "Both were supplied."
            )
        if is_string(filter_params):
            if filter_params == "latest":
                filter_id = self.web3.manager.request_blocking(
                    "eth_newBlockFilter", [],
                )
                return BlockFilter(self.web3, filter_id)
            elif filter_params == "pending":
                filter_id = self.web3.manager.request_blocking(
                    "eth_newPendingTransactionFilter", [],
                )
                return TransactionFilter(self.web3, filter_id)
            else:
                raise ValueError(
                    "The filter API only accepts the values of `pending` or "
                    "`latest` for string based filters"
                )
        elif isinstance(filter_params, dict):
            _filter_id = self.web3.manager.request_blocking(
                "eth_newFilter",
                [filter_params],
            )
            return LogFilter(self.web3, _filter_id)
        elif filter_id and not filter_params:
            return LogFilter(self.web3, filter_id)
        else:
            raise TypeError("Must provide either filter_params as a string or "
                            "a valid filter object, or a filter_id as a string "
                            "or hex.")

    def getFilterChanges(self, filter_id):
        return self.web3.manager.request_blocking(
            "eth_getFilterChanges", [filter_id],
        )

    def getFilterLogs(self, filter_id):
        return self.web3.manager.request_blocking(
            "eth_getFilterLogs", [filter_id],
        )

    def getLogs(self, filter_params):
        return self.web3.manager.request_blocking(
            "eth_getLogs", [filter_params],
        )

    def uninstallFilter(self, filter_id):
        return self.web3.manager.request_blocking(
            "eth_uninstallFilter", [filter_id],
        )

    def contract(self,
                 address=None,
                 **kwargs):
        ContractFactoryClass = kwargs.pop('ContractFactoryClass', self.defaultContractFactory)

        ContractFactory = ContractFactoryClass.factory(self.web3, **kwargs)

        if address:
            return ContractFactory(address)
        else:
            return ContractFactory

    def setContractFactory(self, contractFactory):
        self.defaultContractFactory = contractFactory

    def getCompilers(self):
        return self.web3.manager.request_blocking("eth_getCompilers", [])

    def getWork(self):
        return self.web3.manager.request_blocking("eth_getWork", [])

    def generateGasPrice(self, transaction_params=None):
        if self.gasPriceStrategy:
            return self.gasPriceStrategy(self.web3, transaction_params)

    def setGasPriceStrategy(self, gas_price_strategy):
        self.gasPriceStrategy = gas_price_strategy
