from flask import Flask, request, jsonify, render_template
import oqs

import binascii
from collections import OrderedDict
import psutil
import time


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

        #signer_public_key = signer.generate_keypair()
        #signer_secret_key = signer.export_secret_key()
        secret_key = binascii.unhexlify(self.sender_private_key)
        signer = oqs.Signature("ML-DSA-87-ipd", secret_key)

        message = str(self.to_dict()).encode('utf8')

        # Sign the message (transaction data)
        signature = signer.sign(message)
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

    response = {
        'transaction': transaction.to_dict(),
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
    initial_memory = process.memory_info().rss  # Memory before key generation

    # Measure key generation time
    start_time = time.time()
    signer = oqs.Signature("ML-DSA-87-ipd")
    # Generate keypair
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()

    keygen_time = time.time() - start_time

    # Measure memory usage after key generation
    final_memory = process.memory_info().rss
    keygen_memory_bytes = final_memory - initial_memory  # Memory difference in bytes

    # Measure public & private key size
    public_key_size = len(public_key)
    private_key_size = len(private_key)
    # Create response
    response = {
        'private_key': binascii.hexlify(private_key).decode('ascii'),
        'private_key_size_bytes': private_key_size,
        'public_key': binascii.hexlify(public_key).decode('ascii'),
        'public_key_size_bytes': public_key_size,
        'keygen_time_ms': keygen_time * 1000,  # Convert to milliseconds
        'keygen_memory_bytes': keygen_memory_bytes  # Memory difference
    }

    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8081, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port, debug=True)
