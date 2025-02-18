from flask import Flask, request, jsonify, render_template
import os
import tracemalloc
import time
import pyspx.shake_256s as sphincs

from Crypto.Hash import SHAKE256

#import Crypto
#import Crypto.Random
#from Crypto.PublicKey import RSA
#from Crypto.Signature import PKCS1_v1_5
#from Crypto.Hash import SHA

import binascii
from collections import OrderedDict
class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount
    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'sender_private_key': self.sender_private_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })

    def sign_transaction(self):
        start_time = time.time()
        seed = os.urandom(sphincs.crypto_sign_SEEDBYTES)
        public_key,private_key = sphincs.generate_keypair(seed)
        # Prepare the transaction data to be signed
        transaction_data = str(self.to_dict()).encode('utf8')

        # Hash the transaction data using SHAKE256
        shake = SHAKE256.new()
        shake.update(transaction_data)
        h = shake.read(64)  # Read 64 bytes (512 bits) from the SHAKE256 hash

        #h = SHAKE256.new(str(self.to_dict()).encode('utf8'))
        s = sphincs.sign(h, private_key)
        signature = binascii.hexlify(s).decode('ascii')
        sign_time = time.time() - start_time
        return signature, sign_time

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)
    signature, sign_time = transaction.sign_transaction()

    response = {'transaction': transaction.to_dict(),
                'signature': transaction.sign_transaction(),
                'sign_time_seconds': sign_time}

    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


@app.route('/wallet/new')
# Define the new_wallet function using SPHINCS+
def new_wallet():
    # Measure key generation time and memory usage
    tracemalloc.start()
    start_time = time.time()
    random_gen = os.urandom(sphincs.crypto_sign_SEEDBYTES) #the seed length based on the chosen SPHINCS+ parameter set
    public_key, private_key = sphincs.generate_keypair(random_gen)
    keygen_time = time.time() - start_time
    keygen_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()# Measure public & private key size

    # Measure public & private key size
    public_key_hex = binascii.hexlify(public_key).decode('ascii')
    private_key_hex = binascii.hexlify(private_key).decode('ascii')

    public_key_size = len(public_key_hex)
    private_key_size = len(private_key_hex)

    # Create response
    response = {
        'private_key': private_key_hex,
        'private_key_size_bytes': private_key_size,
        'public_key': public_key_hex,
        'keygen_time_ms': keygen_time * 1000,  # Convert to milliseconds
        'keygen_memory_bytes': keygen_memory[1] - keygen_memory[0],  # Peak memory usage
        'public_key_size_bytes': public_key_size
    }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
