# coding=utf-8

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
        return OrderedDict([
            ('account_ID', self.account_ID),
            ('record', self.record),
        ])

    def sign_transaction(self):
        private_key = RSA.importKey(binascii.unhexlify(self.private_key))
        signer = Signature.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('ascii'))

        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def encrypt_record(self):
        public_key = RSA.importKey(binascii.unhexlify(self.account_ID))
        cipher = Cipher.new(public_key)
        
        for k, v in self.record.items():
            # Creat hash, string -> binary
            h = SHA.new(v.encode('ascii'))

            # Encrypt, binary(msg) + binary(hash) -> binary
            ciphertext = cipher.encrypt(v.encode('ascii') + h.digest())

            # Save, binary -> hexa -> ascii
            self.record[k] = binascii.hexlify(ciphertext).decode('ascii')

    def decrypt_record(self, encrypted_data, private_key):
        private_key = RSA.importKey(binascii.unhexlify(private_key))
        dsize = SHA.digest_size
        # Let's assume that average data length is 15
        sentinel = Crypto.Random.new().read(15+dsize)
        cipher = Cipher.new(private_key)
        message = cipher.decrypt(binascii.unhexlify(encrypted_data), sentinel)
        digest = SHA.new(message[:-dsize]).digest()

        if digest == message[-dsize:]:
            return message[:-dsize].decode('ascii')
        else:
            return False


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


@app.route('/view/record')
def view_record():
    return render_template('/view_record.html'), 200


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

    return jsonify(response), 200


# @app.route('/view/record/decrypt')
# def view_record_decrypt():
#     name = request.args.get('name','', type=str)
#     date_of_birth = request.args.get('date_of_birth','', type=str)
#     medical_notes = request.args.get('medical_notes','', type=str)
#     blood_type = request.args.get('blood_type','', type=str)
#     weight = request.args.get('weight','', type=str)
#     height = request.args.get('height','', type=str)
#     emergency_contact = request.args.get('emergency_contact','', type=str)
#     valid_through = request.args.get('valid_through','', type=str)

#     response = {
#         'name': decrypt_record(name),
#         'date_of_birth': decrypt_record(date_of_birth),
#         'medical_notes': decrypt_record(medical_notes),
#         'blood_type': decrypt_record(blood_type),
#         'weight': decrypt_record(weight),
#         'height': decrypt_record(height),
#         'emergency_contact': decrypt_record(emergency_contact),
#         'valid_through': decrypt_record(valid_through),
#     }

#     return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='listening port')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
