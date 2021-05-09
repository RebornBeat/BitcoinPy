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

    def check_for_chain():
        if not os.path.isfile(Chain_Path):
            return
        try:
            with open(Chain_Path, "r") as f:
                imported_chain = json.load(f)
                chain_length = len(imported_chain)
                logger.info(f"Loading chain from disk with {chain_length} blocks")
                for block in imported_chain:
                    connect_block(block)
        except Exception:
            logger.exception('Failed to load chain, starting from genesis')


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


if __name__ == '__main__':

    logging.basicConfig(filename='BitCoinPyLog.log', filemode='a', encoding='utf-8')

    logger = logging.getLogger(__name__)

    Wallet_Path = os.getcwd() + '\wallet.dat'

    signing_key, verifying_key, my_address = get_wallet()

    Chain_Path = os.getcwd() + '\chain.dat'

    blockchain = BlockChain()

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


