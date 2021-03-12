import hashlib
import random
import p521
from simon import SimonCipher

# returns a list where each element is a hex string
# that represents 16 bytes IOW 128 bits when the
# hex string is converted to an int representation
def simon_prep(plaintext):
	ret = []
	text = plaintext
	length = len(text)
	rem = length%32
	if rem != 0:
		text = text.zfill((length+32-rem))
	length = len(text)
	i = 0
	while(i < length):
		ret.append(text[i:i+32])
		i += 32
	return ret

# takes as input decrypted ciphertext
# returns (r, s, A_prime, message) values recovered
# from decrypted ciphertext
def recover(recovered_text, r):
	text = ''
	for w in recovered_text:
		text = text + w
	text = '00'+text
	str_r = text[0:131]
	str_s = text[131:263]
	str_A_prime = text[263:395]
	message = text[395:]

	s = int(str_s, 16)
	A_prime = p521.point_decompression(str_A_prime)
	return (r, s, A_prime, message)


def foo():
	return '1'.zfill(132)

def main():
	random.seed(1)
	a = p521.create_private()
	b = p521.create_private()
	A = p521.create_public(a)
	B = p521.create_public(b)
	print('a =', hex(a))
	print('b =', hex(b))
	print('A = ('+hex(A[0])+', '+hex(A[1])+')')
	print('B = ('+hex(B[0])+', '+hex(B[1])+')')

	a_prime = p521.create_private()
	b_prime = p521.create_private()
	A_prime = p521.create_public(a_prime)
	B_prime = p521.create_public(b_prime)

	print('a\' =', hex(a))
	print('b\' =', hex(b))
	print('A\' = ('+hex(A_prime[0])+', '+hex(A_prime[1])+')')
	print('B\' = ('+hex(B_prime[0])+', '+hex(B_prime[1])+')')

	y_sign = p521.determine_sign(A_prime[1])
	A_prime_c = p521.point_compression(hex(A_prime[0]), y_sign)

	# "Bond. James Bond."
	message = '426f6e642e204a616d657320426f6e642e'
	A_p_m = A_prime_c+message
	str_sha3_hash = hashlib.new('sha3_512', A_p_m.encode()).hexdigest()
	sha3_hash = int(str_sha3_hash, 16)

	x = p521.create_ephemeral()
	print('ephemeral x =', x)

	(r, s) = p521.sign(sha3_hash, x, a)

	str_r = hex(r)[2:].zfill(132)
	str_s = hex(s)[2:].zfill(132)
	text = str_r+str_s+A_p_m

	k = p521.point_mul(B[0], B[1], x)
	print('Alice computes secret key k =', hex(k[0]))
	y_sign = p521.determine_sign(k[1])
	k_x = p521.point_compression(hex(k[0]), y_sign)

	my_simon = SimonCipher(k[0], key_size=256, block_size=128)
	plaintext = simon_prep(text)

	X = p521.base_point_mul(x)
	y_sign = p521.determine_sign(X[1])
	X_x = p521.point_compression(hex(X[0]), y_sign)

	print('before ecnryption X_x =', X_x)
	print('before encryption r = '+str_r)
	print('before encryption s = '+str_s)
	print('before encryption A\' = '+A_prime_c)
	print('before encryption message = '+message)

	ciphertext = []
	for t in plaintext:
		ciphertext.append(my_simon.encrypt(int(t, 16)))
	ciphertext.insert(0, X_x)

	text = ''
	for i in range(1, len(ciphertext)):
		text = text + hex(ciphertext[i])[2:]
	print('after ecnryption X_x =', X_x)
	print('after encryption (r, s, A\', message) = '+text)
	
	recovered_X = p521.point_decompression(ciphertext[0])
	recovered_k = p521.point_mul(recovered_X[0], recovered_X[1], b)
	print('Bob computes secret key k =', hex(recovered_k[0]))
	print('It is '+str(k[0]==recovered_k[0])+' that Alice and Bob compute the same scret key')
	#print(X)
	#print(recovered_X)
	#print(recovered_k[0] == k[0])

	ciphertext = ciphertext[1:]
	my_simon = SimonCipher(recovered_k[0], key_size=256, block_size=128)
	recovered_text = []
	for t in ciphertext:
		recovered_text.append(hex(my_simon.decrypt(t))[2:])
	#print(ciphertext)
	#print(recovered_text)

	(recovered_r, recovered_s, recovered_A_prime, recovered_message) = recover(recovered_text, r)
	
	(signature_verified, key_used) = p521.verify(recovered_r, recovered_s, A, recovered_A_prime, sha3_hash)

	if(signature_verified):
		print('signature verified with key '+key_used)

	print('after decryption X_x =', X_x)
	print('after decryption =', hex(recovered_r))
	print('after decryption s =', hex(recovered_s))
	print('after decryption A\' = ('+hex(recovered_A_prime[0])+', '+hex(recovered_A_prime[1])+')')
	if(A_prime[0]==recovered_A_prime[0] and A_prime[1]==recovered_A_prime[1]):
		print('test case for compressing and decompressing A\' works')
	print('efter decryption message = '+message)

if __name__ == '__main__':
	main()