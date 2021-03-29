import os
import pickle
import hashlib
import binascii
import multiprocessing

from ellipticcurve.privateKey import PrivateKey

def generate_private_key():

         return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()

def private_key_to_public_key(private_key):

	pk = PrivateKey().fromString(bytes.fromhex(private_key))
	return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):

	output = []
	alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	var = hashlib.new('ripemd160')
	encoding = binascii.unhexlify(public_key.encode())
	var.update(hashlib.sha256(encoding).digest())
	var_encoded = ('00' + var.hexdigest()).encode()
	digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
	var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
	count = [char != '0' for char in var_hex].index(True) // 2
	n = int(var_hex, 16)
	while n > 0:
		n, remainder = divmod(n, 58)
		output.append(alphabet[remainder])
	for i in range(count): output.append(alphabet[0])
	return ''.join(output[::-1])

def private_key_to_WIF(private_key):

	digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
	var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
	var = binascii.unhexlify('80' + private_key + var[0:8])
	alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	value = pad = 0
	result = ''
	for i, c in enumerate(var[::-1]): value += 256**i * c
	while value >= len(alphabet):
		div, mod = divmod(value, len(alphabet))
		result, value = chars[mod] + result, div
	result = chars[value] + result
	for c in var:
		if c == 0: pad += 1
		else: break
	return chars[0] * pad + result


def main(data):

	while True:
		private_key = generate_private_key()
		public_key = private_key_to_public_key(private_key) 	 # 0.0031567731 seconds
		address = public_key_to_address(public_key)		 # 0.0000801390 seconds
		process(private_key, public_key, address) 	         # 0.0000026941 seconds
									 # --------------------
									 # 0.0032457721 seconds


def process(private_key, public_key, address):

        

        with open('address.txt', 'a') as file:
                file.write('hex-private: ' + str(private_key) + '\n'
                           'WIF-Private: ' + str(private_key_to_WIF(private_key)) + '\n' +
                           'WIF-address: ' + str(address) + '\n' +
                           'publickey  : ' + str(public_key) + '\n\n')
                
                print(str(address))


if __name__ == '__main__':

	data = [set() for _ in range(4)]

	for cpu in range(multiprocessing.cpu_count()):
		multiprocessing.Process(target = main, args = (data, )).start()

