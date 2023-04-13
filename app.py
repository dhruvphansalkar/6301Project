from flask import Flask,redirect,url_for
from flask import request
from flask import render_template
from flask import send_file
from Crypto.PublicKey import RSA
import os
import sys
import zipfile
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5
import hashlib

app = Flask(__name__, static_folder='static', static_url_path='')

signHex = ''

@app.route('/senderkeygenerate')
def sender_generate():
	return render_template("sender-key.html")

@app.route('/receiverkeygenerate')
def receive_generate():
	return render_template("receiver-key.html")

#Generates the keys for the sender and stores them in the static folder
@app.route('/keygen/sender')
def sengen():
	password = request.args.get('password')
	keyPair = RSA.generate(1024)
	f = open("./static/sender/A_PrivateKey.pem", "wb")
	f.write(keyPair.exportKey("PEM",password))
	f.close()

	f = open("./static/sender/A_PublicKey.txt", "wb")
	f.write(keyPair.publickey().exportKey('OpenSSH'))
	f.close()
	return redirect('/sengenerated')

#Generates the keys for the sender and stores them in the static folder
@app.route('/keygen/receiver')
def recgen():
	password = request.args.get('password')
	keyPair = RSA.generate(1024)
	f = open("./static/receiver/B_PrivateKey.pem", "wb")
	f.write(keyPair.exportKey("PEM",password))
	f.close()

	f = open("./static/receiver/B_PublicKey.txt", "wb")
	f.write(keyPair.publickey().exportKey('OpenSSH'))
	f.close()
	return redirect('/recgenerated')

@app.route('/sengenerated')
def sengend():
	return render_template("generated-sender.html")
@app.route('/recgenerated')
def recgend():
	return render_template("generated-receiver.html")

#download sender public key
@app.route('/dspub')
def dspub():
	return send_file('./static/sender/A_PublicKey.txt', as_attachment=True)

#download sender private key
@app.route('/dspri')
def dspri():
	return send_file('./static/sender/A_PrivateKey.pem', as_attachment=True)

#download receiver public key
@app.route('/drpub')
def drpub():
	return send_file('./static/receiver/B_PublicKey.txt', as_attachment=True)

#download receiver private key
@app.route('/drpri')
def drpri():
	return send_file('./static/receiver/B_PrivateKey.pem', as_attachment=True)

#download encrypted file
@app.route('/downenc')
def downenc():
	return send_file(os.path.join(app.config['UPLOAD_FOLDER'], "encrypted.txt.enc"), as_attachment=True)

#download decrypted file
@app.route('/downdec')
def downdec():
	return send_file(os.path.join(app.config['DOWNLOAD_FOLDER'], "encrypted.txt"), as_attachment=True)

@app.route('/error')
def error():
	return render_template('error.html')

@app.route('/signauth')
def signauth():
	return render_template('signauth.html')

app.config['UPLOAD_FOLDER'] = "./static/upload"
app.config['DOWNLOAD_FOLDER'] = "./static/download" 

@app.route('/')
def homepage():
	return render_template("home.html")
@app.route('/key')
def banana():
	return render_template("input.html")
	
################################################################
@app.route('/upload/',methods = ['GET','POST'])
def upload_file():
	if request.method =='POST':
		file = request.files['file[]']
		if file:
			filename = "encrypted.txt"
			name = os.path.join(app.config['UPLOAD_FOLDER'],filename)
			file.save(name)
	return redirect('/key1')

@app.route('/key1')
def banana1():
	return render_template("input1.html")

@app.route('/encrypt')
def encrypt():
	print('break point here')
	password = request.args.get('password')
	file = request.args.get('file')
	file = os.path.join(app.config['UPLOAD_FOLDER'],file)
	# Define public and private key names for faster usage
	# Sender's private key:
	priKey = "./static/sender/A_PrivateKey.pem"
	# Receiver's public key:
	pubKey = "./static/receiver/B_PublicKey.txt"

	def encrypt_and_sign(file_name, receiver_pub_key_file_name, sender_priv_key_file_name, password):
	# read file
		with open(file_name, "rb") as f:
			file_data = f.read()

		# create signature
		private_key = RSA.import_key(open(sender_priv_key_file_name).read(), password)
		h = SHA256.new(file_data)
		signer = PKCS1_v1_5.new(private_key)
		signature = signer.sign(h)

		# encrypt file with AES-CFB
		iv = Random.new().read(AES.block_size)
		key = hashlib.sha256(Random.new().read(1024)).digest()
		cipher = AES.new(key, AES.MODE_CFB, iv)
		enc_data = iv + cipher.encrypt(file_data)

		# encrypt key with RSA-OAEP
		receiver_pub_key = RSA.import_key(open(receiver_pub_key_file_name).read())
		cipher_rsa = PKCS1_OAEP.new(receiver_pub_key)
		enc_key = cipher_rsa.encrypt(key)

		# write encrypted data and signature to file
		with open(file_name + ".enc", "wb") as f:
			f.write(enc_data)

		with open(file_name + ".sig", "wb") as f:
			f.write(signature)

		with open(file_name + ".key", "wb") as f:
			f.write(enc_key)

	encrypt_and_sign(file, pubKey, priKey, password)
	return redirect("/generated1")







@app.route('/generated1')
def inp2():
	return render_template("encrypted.html")   



########################################################################################

@app.route('/key2')
def banana2():
	return render_template("input2.html")
@app.route('/decrypt')
def decrypt():
	# Define public and private key names for faster usage
	password = request.args.get('password')
	file = request.args.get('file')
	down_file = os.path.join(app.config['DOWNLOAD_FOLDER'],file)
	file = os.path.join(app.config['UPLOAD_FOLDER'],file)
	
	# Sender's public key:
	pubKey = "./static/sender/A_PublicKey.txt"
	# Receiver's private key:
	priKey = "./static/receiver/B_PrivateKey.pem"

	def decrypt_and_verify(file_name, sender_pub_key_file_name, receiver_priv_key_file_name, password):
    # read encrypted data and signature from file
		with open(file_name + ".enc", "rb") as f:
			enc_data = f.read()

		with open(file_name + ".sig", "rb") as f:
			signature = f.read()

		with open(file_name + ".key", "rb") as f:
			enc_key = f.read()

		# decrypt key with RSA-OAEP
		private_key = RSA.import_key(open(receiver_priv_key_file_name).read(), password)
		cipher_rsa = PKCS1_OAEP.new(private_key)
		key = cipher_rsa.decrypt(enc_key)

		# decrypt data with AES-CFB
		iv = enc_data[:AES.block_size]
		cipher = AES.new(key, AES.MODE_CFB, iv)
		file_data = cipher.decrypt(enc_data[AES.block_size:])

		# verify signature
		public_key = RSA.import_key(open(sender_pub_key_file_name).read())
		h = SHA256.new(file_data)
		verifier = PKCS1_v1_5.new(public_key)
		if not verifier.verify(h, signature):
			raise ValueError("Invalid signature")

		# write decrypted data to file
		with open(down_file, "wb") as f:
			f.write(file_data)

	decrypt_and_verify(file, pubKey, priKey, password)
	return redirect("/generated2")

@app.route('/generated2')
def inp3():
	global signHex
	print(signHex)
	return render_template("done.html", signature=signHex)

if __name__ == '__main__':
	app.run(host=os.getenv('IP', '0.0.0.0'),port=int(os.getenv('PORT', 8080)))