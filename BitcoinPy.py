#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      Admin
#
# Created:     08/05/2021
# Copyright:   (c) Admin 2021
# Licence:     <your licence>
#-------------------------------------------------------------------------------
import hashlib
import time
import socket
import os
import logging
import ecdsa
import hashlib
from base58 import b58encode_check
import binascii
import json
import socket
import random
import struct


class Block(object):

    def __init__(self, index, proof_number, previous_hash, txns, timestamp=None):

        self.index = index

        self.proof_number = proof_number

        self.previous_hash = previous_hash

        self.txns = txns

        self.timestamp = timestamp or time.time()

    def form(self):

        return { "index": self.index, "proof_number": self.proof_number, "previous_hash": self.previous_hash, "txns": self.txns, "timestamp": self.timestamp}

class BlockChain(object):

    def __init__(self):

        self.chain = []

        self.txns = []

        self.nodes = set()

        self.build_genesis()

    def build_genesis(self):

        self.build_block(proof_number=0, previous_hash=0, timestamp=1501821412)

    def build_block(self, proof_number, previous_hash, timestamp=None):

        block = Block(

            index = len(self.chain),

            proof_number = proof_number,

            previous_hash = previous_hash,

            txns = self.txns,

            timestamp = timestamp

        ).form()

        self.txns = []

        self.chain.append(block)

        return block

    @staticmethod

    def confirm_validity(block, previous_block):

        if previous_block.index + 1 != block.index:

            return False

        elif previous_block.compute_hash != block.previous_hash:

            return False

        elif block.timestamp <= previous_block.timestamp:

            return False

        return True

    def add_txns(self, sender, receiver, amount):

        self.txns.append({

            'sender': sender,

            'receiver': receiver,

            'amount': amount

        })

        return True

    @staticmethod

    def proof_of_work(last_proof):

        pass

    @property

    def latest_block(self):

        return self.chain[-1]


    def compute_hash(self, block):

        index = block['index']

        proof_number = block['proof_number']

        previous_hash = block['previous_hash']

        txns = block['txns']

        timestamp = block['timestamp']

        string_block = "{}{}{}{}{}".format(index, proof_number, previous_hash, txns, timestamp)

        hashed_block =  hashlib.sha256(string_block.encode()).hexdigest()

        return hashed_block

    def chain_validity(self):

        pass

    def block_mining(self, details_miner):

        self.get_data(

            sender="0", #it implies that this node has created a new block

            receiver=details_miner,

            quantity=1, #creating a new block (or identifying the proof number) is awared with 1

        )

        last_block = self.latest_block

        last_proof_number = last_block.proof_number

        proof_number = self.proof_of_work(last_proof_number)

        last_hash = last_block.compute_hash

        block = self.build_block(proof_number, last_hash)

        return vars(block)

    def create_node(self, address):

        self.nodes.add(address)

        return True

    @staticmethod

    def get_block_object(block_data):

        return Block(

            block_data['index'],

            block_data['proof_number'],

            block_data['previous_hash'],

            block_data['data'],

            timestamp=block_data['timestamp']

        )


    def check_for_corruption():
        pass

class Connection(object):
    def __init__(self):
        self.magic_value = 0xd9b4bef9
        self.my_address = "127.0.0.1"
        self.target_port = 8333

    def create_sub_version(self):
        sub_version = "/Satoshi:0.7.2/"
        return b'\x0F' + sub_version.encode()

    def encoded_network_address(self, ip_address):
        print(ip_address)
        network_address = struct.pack('>8s16sH', b'\x01', bytearray.fromhex("00000000000000000000ffff") + socket.inet_aton(ip_address), self.target_port)
        return(network_address)

    def create_message(self, command, payload):
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
        return(struct.pack('L12sL4s', self.magic_value, command.encode(), len(payload), checksum) + payload)

    def create_message_verack(self):
        return bytearray.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")

    def create_payload_version(self, seed):
        version = 60002
        services = 1
        timestamp = int(time.time())
        print(self.my_address)
        addr_local = self.encoded_network_address(ip_address = self.my_address)
        addr_peer = self.encoded_network_address(seed)
        nonce = random.getrandbits(64)
        start_height = 0
        payload = struct.pack('<LQQ26s26sQ16sL', version, services, timestamp, addr_peer, addr_local, nonce, self.create_sub_version(), start_height)
        return(payload)

    def responce_format(self, command, request_data, response_data):
        print("")
        print("Command: " + command)
        print("Request:")
        print(request_data)
        print("Response:")
        print(response_data)
        print("")


def get_wallet():

    if os.path.isfile(Wallet_Path):
        with open(Wallet_Path, 'rb') as f:
            signing_key = ecdsa.SigningKey.from_string(f.read(), curve=ecdsa.SECP256k1)
    else:
        #logger.info("New Wallet Generated:", Wallet_Path)
        print("New Wallet Generated:", Wallet_Path)
        signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        #logger.info(signing_key)
        print(signing_key)
        with open(Wallet_Path, 'wb') as f:
            f.write(signing_key.to_string())

    verifying_key = signing_key.get_verifying_key()
    sha = hashlib.sha256(verifying_key.to_string()).digest()
    print("Sha", sha)
    ripe = hashlib.new('ripemd160', sha).digest()
    print("Ripe", ripe)
    my_address = b58encode_check(b'\x00' + ripe)
    #logger.info("your address is:", my_address.decode("utf-8"))
    print("your address is:", my_address.decode("utf-8"))

    return signing_key, verifying_key, my_address

def check_for_chain():
    if not os.path.isfile(Chain_Path):
        #logger.info('No chain found, starting from genesis')
        print('No chain found, connecting to DNS Seeds')
        connect_to_seeds()
        return
    try:
        with open(Chain_Path, "r") as f:
            imported_chain = json.load(f)
            chain_length = len(imported_chain)
            logger.info(f"Loading chain from disk with {chain_length} blocks")
            for block in imported_chain:
                check_for_corruption(block)
    except Exception:
        logger.exception('Failed to load chain, starting from genesis')


if __name__ == '__main__':

    logging.basicConfig(filename='BitCoinPyLog.log', filemode='a', encoding='utf-8')

    logger = logging.getLogger(__name__)

    DNS_SEEDS = [
        "seed.bitcoinstats.com",
        "seed.bitcoin.sipa.be",
        "dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "bitseed.xf2.org"
    ]

    Wallet_Path = os.getcwd() + '\wallet.dat'

    signing_key, verifying_key, my_address = get_wallet()

    Chain_Path = os.getcwd() + '\chain.dat'

    blockchain = BlockChain()

    check_for_chain()

    print("GET READY MINING ABOUT TO START")

    print(blockchain.chain)

    last_block = blockchain.latest_block

    print("Last Block", last_block)

    last_proof_number = last_block['proof_number']

    proof_number = blockchain.proof_of_work(last_proof_number)

    blockchain.add_txns(

        sender="0", #this means that this node has constructed another block

        receiver="Christian",

        amount=1, #building a new block (or figuring out the proof number) is awarded with 1

    )

    print(last_block)

    last_hash = blockchain.compute_hash(last_block)

    block = blockchain.build_block(proof_number, last_hash)

    print("WOW, MINING HAS BEEN SUCCESSFUL!")

    print(blockchain.chain)

    logging.shutdown()


