import math
import random
from sympy import isprime

a = -3
b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
p = pow(2,521)-1
q = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
P_x = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
P_y = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650

def point_add(x1, y1, x2, y2):
	s = ((y2-y1)*pow((x2-x1),-1, p)) % p
	x3 = (s**2 - x1 - x2) % p
	y3 = (s*(x1 - x3) - y1) % p
	return (x3, y3)

def point_double(x1, y1):
	s = ((3*x1**2+a)*pow((2*y1), -1, p)) % p
	x3 = (s**2 - x1 - x1) % p
	y3 = (s*(x1 - x3) - y1) % p
	return (x3, y3)

def point_mul(x1, y1, n):
	x = x1
	y = y1
	d = list(f'{n:b}')
	for i in range(1, len(d)):
		(x, y) = point_double(x,y)
		if d[i] == '1':
			(x, y) = point_add(x,y,x1,y1)
	return (x, y)

def base_point_mul(n):
	(x, y) = point_mul(P_x, P_y, n)
	return (x, y)

def create_private():
	return random.randint(1, q-1)

def create_ephemeral():
	return random.randint(1, q-1)

def create_public(private):
	return point_mul(P_x, P_y, private)

def sign(message, ephemeral, private):
	(R_x, R_y) = point_mul(P_x, P_y, ephemeral)
	r = R_x

	ephemeral_inv = pow(ephemeral, -1, q)
	s = ((message+private*r)*ephemeral_inv)%q
	return (r, s)

# returns 0 if y positive
# returns 1 if y negative
def determine_sign(y):
	y_sqr = (y*y)%p
	inv_4 = pow((y_sqr*y_sqr*y_sqr*y_sqr)%p, -1, p)
	pos = pow(y_sqr, int((p+1)/4), p)
	neg = (-1*pow(y_sqr, int((p+1)/4), p))%p
	if y == pos:
		return 0
	else:
		return 1

# takes in hex string of x value and sign of y
# returns 66 byte in a 132 byte hex string format
def point_compression(hex_str, sign):
	x = hex_str[2]
	ret = hex(int(x, 16)+2*sign)[2:]+hex_str[3:]
	return ret.zfill(132)

# takes as input 66byte compressed point in hex_string
# format
# returns (x, y) pair where (x, y) are the x and y
# point values
def point_decompression(hex_str):
	x = int(hex(int(hex_str[1], 16)&1)+hex_str[2:], 16)
	y_sqr = x*x*x+a*x+b
	inv_4 = pow((y_sqr*y_sqr*y_sqr*y_sqr)%p, -1, p)
	pos = pow(y_sqr, int((p+1)/4), p)
	neg = (-1*pow(y_sqr, int((p+1)/4), p))%p
	if((int(hex_str[1],16)&2) == 2):
		return (x, (-1*pow(y_sqr, int((p+1)/4), p))%p)
	else:
		return (x, pow(y_sqr, int((p+1)/4), p))

def verify(r, s, A, A_prime, hash_x):
	w = pow(s, -1, q)
	u1 = (w*hash_x)%q
	u2 = (w*r)%q
	(u1P_x, u1P_y) = point_mul(P_x,P_y,u1)
	(u2A_x, u2A_y) = point_mul(A[0],A[1],u2)
	(V_x, V_y) = point_add(u1P_x, u1P_y, u2A_x, u2A_y)

	v = V_x
	if(v%q == r%q):
		return True, 'A'

	(u2A_x, u2A_y) = point_mul(A_prime[0],A_prime[1],u2)
	(V_x, V_y) = point_add(u1P_x, u1P_y, u2A_x, u2A_y)
	v = V_x
	if(v%q == r%q):
		return True, 'A\''
	return False, ''

def main():
	"""
	n = 457351 #ephemeral
	private = 1537540

	(B_x, B_y) = pointMult(P_x,P_y,private,a,p)
	print('B_x =', B_x)
	print('B_y =', B_y)

	(R_x, R_y) = pointMult(P_x,P_y,n,a,p)
	print('R_x =,', R_x)
	print('R_y =,', R_y)

	x = 0x777196555de9a55a506c5c8be936e9438e979ed58814a62eb361b89c316ef61714affcc03cad7912bc7696324e5f958aae2b7b517ec5b1db1441915f9b5be446
	r = R_x
	print('xr mod q is equivalent to', (x*r)%q)

	inv_n = pow(n, -1, q) #ephemeral inverse
	print('inv_n =', inv_n)

	s = ((x+private*r)*inv_n)%q
	print('r =', r)
	print('s =', s)

	w = pow(s, -1, q)
	u1 = (w*x)%q
	u2 = (w*r)%q
	(u1P_x, u1P_y) = pointMult(P_x,P_y,u1,a,p)
	(u2B_x, u2B_y) = pointMult(B_x,B_y,u2,a,p)
	(V_x, V_y) = pointAdd(u1P_x, u1P_y, u2B_x, u2B_y, p)
	v = V_x
	print('w =', w)
	print('u1 =', u1)
	print('u2 =', u2)
	print('V_x =', V_x)
	print('V_y =', V_y)
	print('v == r is', v%q == r%q)


	(x,y) = pointMult(5,1,10,2,17)
	print('x =', x)
	print('y =', y)
	"""

	return

if __name__ == '__main__':
	main()