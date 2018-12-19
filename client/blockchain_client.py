from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature
from Crypto.Cipher import PKCS1_v1_5 as Cipher

import requests
from flask import Flask, jsonify, request, render_template


class Transaction:
    def __init__(self, account_ID, private_key, record):
        self.account_ID = account_ID
        self.private_key = private_key
        self.record = record

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return {
            'account_ID': self.account_ID,
            'record': self.record
            }

    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.private_key))
        signer = Signature.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))

        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def encrypt_record(self):
        public_key = RSA.importKey(binascii.unhexlify(self.account_ID))
        cipher = Cipher.new(public_key)
        
        for k, v in self.record.items():
            # Creat hash, string -> binary
            h = SHA.new(str(self.record[k]).encode('utf8'))

            # Encrypt, binary(msg) + binary(hash) -> binary
            ciphertext = cipher.encrypt(v.encode('utf8') + h.digest())

            # Save, binary -> hexa -> ascii
            self.record[k] = binascii.hexlify(ciphertext).decode('ascii')



app = Flask(__name__)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/create/record')
def make_transaction():
    return render_template('./create_record.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


@app.route('/account/new', methods=['GET'])
def new_account():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'account_ID': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
    }

    return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    account_ID = request.form['account_ID']
    private_key = request.form['private_key']
    record = OrderedDict({
        'name': request.form['name'],
        'date_of_birth': request.form['date_of_birth'],
        'medical_notes': request.form['medical_notes'],
        'blood_type': request.form['blood_type'],
        'weight': request.form['weight'],
        'height': request.form['height'],
        'emergency_contact': request.form['emergency_contact'],
        'valid_through': request.form['valid_through']
    })

    transaction = Transaction(account_ID, private_key, record)

    # Encrypt record
    transaction.encrypt_record()

    response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

    # print(response)

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='listening port')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
