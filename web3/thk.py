from eth_account import (
    Account,
)

from web3._utils.threads import (
    Timeout,
)

from collections import (
    Mapping,
)

from eth_keys import (
    keys
)

from web3.exceptions import (
    TimeExhausted,
)

from eth_utils import (
    apply_to_return_value,
    is_checksum_address,
    keccak as eth_utils_keccak,
    is_string,
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
    defaultPrivateKey = None
    defaultAddress = None
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

    def compileContract(self, chainId, contractText):
        return self.web3.manager.request_blocking(
            "CompileContract",
            {
                "chainId": chainId,
                "contract": contractText
            }
        )

    @deprecated_for("w3.eth.getTransactionByBlock")
    def getTransactionFromBlock(self, block_identifier, transaction_index):
        """
        Alias for the method getTransactionByBlock
        Depreceated to maintain naming consistency with the json-rpc API
        """
        return self.getTransactionByBlock(block_identifier, transaction_index)

    def replaceTransaction(self, transaction_hash, new_transaction):
        current_transaction = get_required_transaction(self.web3, transaction_hash)
        return replace_transaction(self.web3, current_transaction, new_transaction)

    def modifyTransaction(self, transaction_hash, **transaction_params):
        assert_valid_transaction_params(transaction_params)
        current_transaction = get_required_transaction(self.web3, transaction_hash)
        current_transaction_params = extract_valid_transaction_params(current_transaction)
        new_transaction = merge(current_transaction_params, transaction_params)
        return replace_transaction(self.web3, current_transaction, new_transaction)

    # def sendTx(self, chainId, fromAddr, toAddr, nonce, value, input):
    #     return self.web3.manager.request_blocking(
    #         "SendTx",
    #         {
    #             "chainId": chainId,
    #             "from": fromAddr,
    #             "to": toAddr,
    #             "nonce": nonce,
    #             "value": value,
    #             "input": input
    #         }
    #     )

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

    def getStats(self, chainId):
        return self.web3.manager.request_blocking(
            "GetStats",
            {
                "chainId": chainId
            }
        )

    def getTransactions(self, address, startHeight, endHeight):
        return self.web3.manager.request_blocking(
            "GetTransactions",
            {
                "address": address,
                "startHeight": startHeight,
                "endHeight": endHeight
            }
        )

    def getTxByHash(self, chainId, hash):
        return self.web3.manager.request_blocking(
            "GetTransactionByHash",
            {
                "chainId": chainId,
                "hash": hash
            }
        )

    # def callTransaction(self, chainId, fromAddr, toAddr, nonce, value, input):
    #     return self.web3.manager.request_blocking(
    #         "CallTransaction",
    #         {
    #             "chainId": chainId,
    #             "from": fromAddr,
    #             "to": toAddr,
    #             "nonce": nonce,
    #             "value": value,
    #             "input": input
    #         }
    #     )

    def callRawTx(self, transaction):
        return self.web3.manager.request_blocking(
            "CallTransaction", transaction
        )

    def getBlockHeader(self, chainId, height):
        return self.web3.manager.request_blocking(
            "GetBlockHeader",
            {
                "chainId": chainId, "height": height
            }
        )

    def saveContract(self, address, contract):
        return self.web3.manager.request_blocking(
            "SaveContract",
            {
                "contractaddr": address,
                "contract": contract
            }
        )

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

    def signTransaction(self, transaction_dict, private_key):
        if not isinstance(transaction_dict, Mapping):
            raise TypeError("transaction_dict must be dict-like, got %r" % transaction_dict)
        sign_str = transaction_dict["chainId"] + remove_0x_prefix(transaction_dict["from"]) + \
                   remove_0x_prefix(transaction_dict["to"]) + transaction_dict["nonce"] + \
                   transaction_dict["value"] + remove_0x_prefix(transaction_dict["input"])
        sign_bytes = to_bytes(text=sign_str)
        res = eth_utils_keccak(sign_bytes)
        sign_hash = self.account.signHash(to_hex(res), private_key=private_key)
        transaction_dict["sig"] = to_hex(sign_hash.signature)
        pk = keys.PrivateKey(private_key)
        transaction_dict["pub"] = "0x04" + pk.public_key.to_hex()[2:]
        return transaction_dict

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

    def contract(self,
                 address=None,
                 **kwargs):
        ContractFactoryClass = kwargs.pop('ContractFactoryClass', self.defaultContractFactory)

        ContractFactory = ContractFactoryClass.factory(self.web3, **kwargs)

        if address:
            return ContractFactory(address)
        else:
            return ContractFactory

    def waitForTransactionReceipt(self, chainId, transaction_hash, timeout=5):
        try:
            return wait_for_transaction_receipt(self.web3, chainId, transaction_hash, timeout)
        except Timeout:
            raise TimeExhausted(
                "Transaction {} is not in the chain, after {} seconds".format(
                    transaction_hash,
                    timeout,
                )
            )