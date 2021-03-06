# coding=utf-8

from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

MINING_DIFFICULTY = 2

class Blockchain:
    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()

        # Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')

        # Create genesis block
        genesis_message = {
           'code': 'Counting the Stars at Night\n\n' +
                    'In the sky where seasons pass\n' +
                    'Autumn fills the air.\n' +
                    'And ready I wait without worry\n' + 
                    'to count all the stars she bears\n\n' + 
                    'Now the reason I cannot tally\n' +
                    'all the stars impressed on my heart, is\n' +
                    '‘cause the morning soon comes,\n' +
                    'my youth’s not quite done, and\n' +
                    'another night still lays in store\n\n' +
                    '- Yun Dong-ju\n'

        }
        self.create_block(nonce=0, previous_hash=self.hash(genesis_message))

    def register_node(self, node_url):
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def verify_transaction_signature(self, account_ID, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(account_ID))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))

        return verifier.verify(h, binascii.unhexlify(signature))

    def submit_transaction(self, account_ID, record, signature):

        transaction = OrderedDict([
            ('account_ID', account_ID),
            ('record', record)
        ])

        transaction_verification = self.verify_transaction_signature(account_ID, signature, transaction)

        if transaction_verification:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            return False

    def create_block(self, nonce, previous_hash):
        # Add a block of transactions to the blockchain
        block = {'block_number': len(self.chain) + 1,
                 'timestamp': time(),
                 'transactions': self.transactions,
                 'nonce': nonce,
                 'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []

        self.chain.append(block)

        return block

    def hash(self, block):
        # Create a SHA-256 hash of a block
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        # Proof of Work
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()

        return guess_hash[:difficulty] == '0'*difficulty

    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            # Delete the reward transaction
            transactions = block['transactions']
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            # transaction_elements = [
            #     'account_ID',
            #     'record'
            # ]
            # record_elements = [
            #     'name',
            #     'date_of_birth',
            #     'medical_notes',
            #     'blood_type',
            #     'weight',
            #     'height',
            #     'emergency_contact',
            #     'valid_through'
            # ]

            records = []
            for transaction in transactions:
                temp = OrderedDict([
                    ('account_ID',transaction['account_ID']),
                    ('record', OrderedDict([
                        ('name', transaction['record']['name']),
                        ('date_of_birth', transaction['record']['date_of_birth']),
                        ('medical_notes', transaction['record']['medical_notes']), 
                        ('blood_type', transaction['record']['blood_type']),
                        ('weight', transaction['record']['weight']),
                        ('height', transaction['record']['height']),
                        ('emergency_contact', transaction['record']['emergency_contact']),
                        ('valid_through', transaction['record']['valid_through']),
                    ]))
                ])
                records.append(temp)
 
            transactions = records

            # transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbors = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbors:
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False


# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():

    values = request.form

    # Check that the required fields are in the POST'ed data
    required = [
        'account_ID',
        'name',
        'date_of_birth',
        'medical_notes',
        'blood_type',
        'weight',
        'height',
        'emergency_contact',
        'valid_through',
        'signature'
    ]

    if not all(k in values for k in required):
        return 'Missing values', 400

    # Reconstruct
    account_ID = values['account_ID']
    record = OrderedDict([
        ('name', values['name']),
        ('date_of_birth', values['date_of_birth']),
        ('medical_notes', values['medical_notes']),
        ('blood_type', values['blood_type']),
        ('weight', values['weight']),
        ('height', values['height']),
        ('emergency_contact', values['emergency_contact']),
        ('valid_through', values['valid_through'])
    ])
    signature = values['signature']

    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(account_ID, record, signature)

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {
            'message': 'Transaction will be added to Block ' + str(transaction_result)}
        return jsonify(response), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = OrderedDict([
        ('chain', blockchain.chain),
        ('length', len(blockchain.chain)),
    ])
    return jsonify(response), 200

@app.route('/chain/transaction/record', methods=['POST'])
def record():
    info = request.form
    account_ID = info.get('account_ID')
    response = {
        'record': [] 
    }

    for block in blockchain.chain:
        for transaction in block['transactions']:
            if transaction['account_ID'] == account_ID:
                response['record'].append(transaction['record'])
            else:
                pass         

    return jsonify(response,), 200


@app.route('/link', methods=['GET'])
def link():
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()
 
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Created",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }

    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
