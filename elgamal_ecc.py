# Language: Python 3
# Run: python3 elgamal_ecc_6.py 9 201
# Parameter 1: <positive_integer_number> - Number of bits to generate the key
# Parameter 2: <integer_number_to_encrypt> - Integer number to encrypt

# importing libraries
import sys, random

# Inverse function - Returning 0 instead of raise an error. Removed gcde
def invm(m, a):
    if a<0:
        a = a + m
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
        else:
            return 0

#Modular exponentiation
def expm(m, a, k):
    if k == 0:
        return 1
    if k == 1:
        return a % m
    if ((k % 2) == 0):
        return expm(m, (a*a)%m, k//2) % m
    return a*expm(m, (a*a)%m, (k-1)//2) % m

#Check if n is prime with t fermat rounds
def is_prime_fermat(n,t):
    for _ in range(1,t+1):
        a = random.randint(1,n-1)
        r = expm(n,a,n-1)
        if r != 1:
            return False
    return True

#Generate a prime number with n-bits, test with fermat rounds, also checks message bts number
def generate_prime_number(n, rounds, message):
    nbit_number = 0
    f = False
    while nbit_number == 2 or nbit_number % 2 == 0 or int.bit_length(nbit_number) != n or nbit_number <= message:
        nbit_number = random.getrandbits(n)
    while not f:
        f = is_prime_fermat(nbit_number, rounds)
        if not f:
            nbit_number += 2
    return (nbit_number)

#ECC addition function
def ecc_add(x1, y1, x2, y2, a, p):
    if (x1 == x2) and (y1 == y2):
        r = (((3 * (x1 * x1)) + a) * invm(p, (y1 * 2))) % p
    else:
        r = ((y2 - y1) * invm(p, (x2 - x1))) % p

    x3 = ((r*r) - x2 - x1) % p
    y3 = ((r*(x1 - x3)) - y1) % p
    return x3, y3

#Find curve points
def ecc_points(rand1,rand2,p):
    curve_points = []
    for i in range(0, p-1):
        [curve_points.append([i,j]) for j in range(0, p-1) if (j*j) % p == (i**3 + (rand1 * i) + rand2) % p]
    #Uncomment the line below to print all curve points
    #print("Curve points:",curve_points)
    return curve_points

#Find curve base points
def ecc_base(curve_points,a,p):
    t = 0
    c = []
    l = len(curve_points)

    while ( t != l ):
        c.append(curve_points[t][0])
        [c.append(ecc_add(curve_points[t][0], curve_points[t][1], curve_points[t][0], curve_points[t][1], a, p)[0]) for _ in range(1, l)]

        if set(curve_points[0]).intersection(set(c)) != 0:
            gx, gy = curve_points[t][0], curve_points[t][1]
            break

        t += 1
        c = []

    return gx, gy

#Creates key - ElGamal ECC
def create_key(gx,gy,a,p):
    # Private Key
    priv = random.randint(2, p - 1)
    print("\nPrivate Key:", priv)

    # Public Key
    x1, y1 = gx, gy
    for _ in range(0, priv):
        x1, y1 = ecc_add(x1, y1, gx, gy, a, p)
    pkx, pky = x1, y1

    # k value
    k = random.randrange(2, p - 1)
    print("\nRandom k:", k)

    c1x, c1y, c2x, c2y = gx, gy, pkx, pky
    for _ in range(0, k):
        c1x, c1y = ecc_add(c1x, c1y, gx, gy, a, p)
        c2x, c2y = ecc_add(c2x, c2y, pkx, pky, a, p)

    print("\nKey C1: (%s,%s)" %(c1x,c1y))
    print("\nKey C2: (%s,%s)" %(c2x,c2y))
    return c1x,c1y,c2x,c2y,priv

#Encrypt function - ElGamal ECC
def ecc_encrypt(m,x1,y1,a,p):
    return ecc_add(m, m, x1, y1, a, p)

#Decrypt function - ElGamal ECC
def ecc_decrypt(c1x,c1y,c2x,c2y,priv,a,p):
    t1, t2 = c1x, c1y
    for _ in range(0,priv):
        t1,t2 = ecc_add(t1, t2, c1x, c1y, a, p)
    return ecc_add(t1, (t2*(-1) + p), c2x, c2y, a, p)

#Execution
if len(sys.argv) != 3 or int(sys.argv[1]) < 3:
    print("\nSyntax: {} <positive_integer_number> <integer_number_to_encrypt>\n".format(sys.argv[0]))
    sys.exit(0)

number_of_bits = int(sys.argv[1])
fermat_rounds = 3
m = int(sys.argv[2])

if (m.bit_length() > number_of_bits-1):
    print("\nThe number {} is a {}-bits number. The key lenght (first parameter) should be {} or more \n".format(m, m.bit_length(), m.bit_length()+1))
    sys.exit(0)

p = int(generate_prime_number(number_of_bits, fermat_rounds, m))
print("\nPrime:", p)
a = random.randrange(p, p*2)
b = random.randrange(p, p*2)
print("\n*** Calculating curve points ***")
curve_points = ecc_points(a,b,p)

gx, gy = ecc_base(curve_points,a,p)
print("\nBase point: (%s,%s)" %(gx, gy))

c1x,c1y,c2x,c2y,priv = create_key(gx,gy,a,p)

cipher_x, cipher_y = ecc_encrypt(m,c2x,c2y,a,p)
print("\nCipherText: (%s,%s)" %(cipher_x,cipher_y))

decrypted,_ = ecc_decrypt(c1x,c1y,cipher_x, cipher_y,priv,a,p)
print("\nDecrypted Message: %s" %(decrypted))
