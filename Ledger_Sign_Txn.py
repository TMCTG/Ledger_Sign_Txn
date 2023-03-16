from ledgerblue.comm import getDongle
import struct
import binascii
from web3 import Web3
import rlp
from rlp.sedes import binary, Binary, big_endian_int, BigEndianInt, List, CountableList, boolean
from Crypto.Hash import keccak
from binascii import unhexlify, hexlify


class TransactionLegacy(rlp.Serializable):
    fields = [
        ("nonce", big_endian_int),
        ("gasPrice", big_endian_int),
        ("gas", big_endian_int),
        ("to", Binary.fixed_length(20, allow_empty=True)),
        ("value", big_endian_int),
        ("data", binary),
        ("v", big_endian_int),
        ("r", big_endian_int),
        ("s", big_endian_int),
    ]


def get_ledger_address(offset):
    """
    Query the ledger device for a public ethereum address.
    Offset is the number in the HD wallet tree, starting at 0
    """
    donglePath = parse_bip32_path(offset)

    apdu = bytes.fromhex('e0020000')
    apdu += bytes([len(donglePath) + 1])
    apdu += bytes([len(donglePath) // 4])
    apdu += donglePath

    dongle = getDongle(True)
    result = dongle.exchange(apdu, timeout=60)

    # Parse result
    offset = 1 + result[0]
    address = result[offset + 1: offset + 1 + result[offset]]

    return f'0x{address.decode()}'

def get_offset(address):
    """
    Convert an address to the HD wallet tree offset
    """
    offset = 0
    while address != get_ledger_address(offset):
        offset += 1

    return offset


def parse_bip32_path(offset):
    """
    Convert an offset to a bytes payload to be sent to the ledger
    representing bip32 derivation path.
    """
    # First account/wallet is on this derivation path  -> "44'/60'/0'/0/0"
    # if you want to use the next account -> "44'/60'/1'/0/0"

    path = f"44'/60'/{offset}'/0/0"
    result = b""
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


def ledger_sign(wallet_offset, txn_dict):  # This will prepare the tx, encode it, send it to the ledger for signing, repack it with r,s,v, encode it, and send it (When the last 2 lines of this function are uncommented).
    if txn_dict['data'] == 0 or txn_dict['data'] == "0x": txn_dict['data'] = b''
    if type(txn_dict['to']) != type(b''): txn_dict['to'] = unhexlify(txn_dict['to'].replace('0x', ''))
    if not txn_dict['gas'] >= 21000:
        txn_dict['gas'] = int(w3.eth.estimate_gas({**{k: txn_dict[k] for k in txn_dict if k in ('from', 'nonce', 'to', 'data', 'value')}}))

    transaction_legacy = TransactionLegacy(nonce=txn_dict['nonce'], gasPrice=txn_dict['gasPrice'],
                                           gas=txn_dict['gas'],
                                           to=txn_dict['to'], value=txn_dict['value'],
                                           data=txn_dict['data'], v=txn_dict['chainId'], r=0, s=0)
    encoded_transaction = rlp.encode(transaction_legacy)  # RLP encode the transaction
    print("RLP encoded transaction: %s" % hexlify(encoded_transaction).decode("utf-8"))

    # Per Ethereum standards, Keccak hash rlp encoded transaction
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(encoded_transaction)
    print("Keccak hash of encoded txn: %s" % keccak_hash.hexdigest())

    dongle = getDongle(True)

    donglePath = parse_bip32_path(wallet_offset)  # BIP 32 path to sign with
    apdu = bytearray.fromhex("e0040000")
    apdu.append(len(donglePath) + 1 + len(encoded_transaction))
    apdu.append(len(donglePath) // 4)
    apdu += donglePath + encoded_transaction

    result = dongle.exchange(bytes(apdu))
    r = int(binascii.hexlify(result[1:33]), 16)
    s = int(binascii.hexlify(result[33:65]), 16)
    # From EIP 155, V = chainId * 2 + 35 + recovery_id of public key.
    for parityBit in (0, 1):
        v = txn_dict['chainId'] * 2 + 35 + parityBit
        try:
            assert txn_dict['from'] == w3.eth.account.recoverHash(message_hash=keccak_hash.digest(), vrs=(v, r, s))
            y_parity = bool(parityBit) #Convert to True or False for Type2(EIP 1559) Transactions
            break
        except:
            pass

    print("R: %s" % r)
    print("S: %s" % s)
    print("V: %s" % v)

    signed_transaction_legacy = TransactionLegacy(**{**{k: txn_dict[k] for k in txn_dict if k in TransactionLegacy._meta.field_names}, 'v': v, 'r': r, 's': s})
    encoded_transaction = rlp.encode(signed_transaction_legacy)

    print("encoded signed transaction: %s" % hexlify(encoded_transaction).decode("utf-8"))
    print("Check and broadcast from here: https://flightwallet.github.io/decode-eth-tx/")
    print("Or uncomment the lines below this one to send automatically")
    #       # send raw transaction
    # transaction_result_hash = w3.eth.sendRawTransaction(encoded_transaction)
    # print("Transaction broadcast hash: 0x%s" % hexlify(transaction_result_hash).decode("utf-8"))


w3 = Web3(Web3.HTTPProvider("https://bsc-dataseed.binance.org:443"))

ledger_wallet_offset = 0  # Which ledger wallet to use(0, 1, 2, 3, etc)
txn_dict={}
txn_dict['gasPrice'] = w3.eth.gas_price
txn_dict['gas'] = 0
txn_dict['chainId'] = w3.eth.chain_id
txn_dict['from'] = get_ledger_address(ledger_wallet_offset)
txn_dict['to'] = "0x0000000000000000000000000000000000000000"
txn_dict['value'] = 0
txn_dict['data'] = 0
txn_dict['nonce'] = w3.eth.get_transaction_count(txn_dict['from'])
ledger_sign(ledger_wallet_offset, txn_dict)  # This is currently set up to sign only, not send.
