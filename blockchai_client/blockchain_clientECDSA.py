from flask import Flask, request, jsonify, render_template

from ecdsa import SECP256k1, SigningKey
import binascii
from collections import OrderedDict
import psutil
import time
import hashlib
import json
class Transaction:
    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })

    def sign_transaction(self):
        start_time = time.time()

        # Convert the sender's private key from hex to bytes
        private_key_bytes = bytes.fromhex(self.sender_private_key)
        # Create a SigningKey object from the private key bytes using SECP256k1 curve
        private_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1, hashfunc=hashlib.sha256)
        # Serialize the transaction data
        transaction_data = json.dumps(self.to_dict(), sort_keys=True).encode('utf8')  # Consistent JSON serialization

        # Sign the transaction data
        signature = private_key.sign(transaction_data)


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
    signature_hex = binascii.hexlify(signature).decode('ascii')

    response = {'transaction': transaction.to_dict(),
                'signature': signature_hex,
                'sign_time_mseconds': sign_time  * 1000,
                'Lenght_signature': len(signature)
                }
    return jsonify(response), 200


@app.route('/make/transaction')
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
def view_transactions():
    return render_template('view_transactions.html')


@app.route('/wallet/new')
def new_wallet():

    # Set up psutil for memory measurement
    process = psutil.Process()
    base_memory_usage = process.memory_info().rss  # Base memory usage before operation

    # Measure key generation time
    start_time = time.time()
    private_key = SigningKey.generate(curve=SECP256k1, hashfunc = hashlib.sha256)
    public_key = private_key.get_verifying_key()
    keygen_time = time.time() - start_time

    # Measure memory usage after key generation
    final_memory = process.memory_info().rss
    keygen_memory_bytes = final_memory - base_memory_usage    # Memory difference in bytes


    # Measure public & private key size
    public_key_size = len(binascii.hexlify(public_key.to_string()).decode('ascii'))
    private_key_size = len(binascii.hexlify(private_key.to_string()).decode('ascii'))

    response = {
        'private_key': binascii.hexlify(private_key.to_string()).decode('ascii'),
        'public_key': binascii.hexlify(public_key.to_string()).decode('ascii'),
        'keygen_time_ms': keygen_time * 1000,  # Convert to milliseconds
        'keygen_memory_bytes': keygen_memory_bytes,  # Memory difference
        'public_key_size_bytes': public_key_size,
        'private_key_size_bytes': private_key_size
    }
    print(f"Base memory usage: {base_memory_usage} bytes")
    print(f"Final memory usage: {final_memory} bytes")
    print(f"Memory difference: {keygen_memory_bytes} bytes")
    print(f"Keygen time: {keygen_time} seconds")
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
