# Language: Python 3
# Run: python3 ecrack_5.py 32 12345678901234567890
# Parameter 1: <positive_integer_number> - Number of bits to generate the key
# Parameter 2: <integer_to_encrypt> - Integer number to encrypt

import sys, random

#Extended Euclidean Algorithm
def gcde(a,b):
    if a == 0:
        return (b, 0, 1)
    g, x, y = gcde(b % a, a)
    return (g, y - (b // a) * x, x)

#Modular Inverse
def invm(m,a):
    d, x, y = gcde(a,m)
    if d <= 1:
        return x
    raise ValueError("No Inverse Exist for " + str(a) + " mod " + str(m))

#GCD
def gcd(a,b):
# Using while is way faster than recursion
    while b:
        a,b = b, a%b
    return a


#Modular exponentiation
def expm(m, a, k):
    if k == 0:
        return 1
    if k == 1:
        return a % m
    if ((k % 2) == 0):
        return expm(m, (a*a)%m, k//2) % m
    return a*expm(m, (a*a)%m, (k-1)//2) % m

#Generate keys
def rsaKey(p,q):
    n = p*q
    # Simple calculation of phi(n)
    phi_n = (p-1)*(q-1)
    # draw of e / 1 < e < phi(n) and gcd(e, phi(n)) = 1
    e = random.randrange(phi_n)
    while gcd(e,phi_n) != 1:
      e = random.randrange(phi_n-1)

    # calculation of d
    d = invm(phi_n,e)
    while d<0 :
      d+=phi_n
    print("n,e,d",n,e,d)
    return (n,e,d)

# will return E(n,e)(msg)
def rsaEnc(n,e,msg):
    c = expm(n, msg, e)
    print("n,msg,e,c",n,msg,e,c)
    return c

def rsaDec(n,d,c):
    m = expm(n, c, d)
    print("n,c,d,m",n,c,d,m)
    return m

def rsaDecCRT(c,p,q,d):
    dp = expm(p - 1, d, 1)
    dq = expm(q - 1, d, 1)
    part1 = expm(p, c, dp)
    part2 = expm(q, c, dq)
    qinv = invm(p,q)
    h = (qinv * (part1 - part2)) % p
    m = part2 + h * q
    return m

def ecrack(n,e,c):
    q,p = efactors(n)
    d = invm((p-1)*(q-1),e)
    m = rsaDecCRT(c,p,q,d)
    return m

def is_prime_fermat(n,t):
    for i in range(1,t+1):
        a = random.randint(1,n-1)
        r = expm(n,a,n-1)
        if r != 1:
            return False
    return True

#Generate a prime number with n-bits, test with fermat rounds, also checks message bts number
def generate_possible_prime_number(n, rounds):
    dbit_number = 0
    f = False
    while dbit_number == 2 or dbit_number % 2 == 0 or int.bit_length(dbit_number) != n:
        dbit_number = random.getrandbits(n)
    while not f:
        #print("Testing Number: {}".format(dbit_number))
        f = is_prime_fermat(dbit_number, rounds)
        if not f:
            dbit_number += 2
    return (dbit_number)

def efactors(n):
    if n <= 3:
        p = n; q = 1
        return p, q
    if n == 4:
        p = 2; q = 2
        return p, q
    if n % 2 == 0:
        print("\nThe number {} is an even number!\n".format(n))
        sys.exit(0)
    x = 2
    y = 2
    p = 1
    f = lambda x: (x**2 + 1) % n
    while p == 1:
        x = f(x)
        y = f(f(y))
        p = gcd(abs(x-y), n)
    q = n // p
    if q == 1:
        print("\nThe number {} is a PRIME number!\n".format(n))
        sys.exit(0)
    if not is_prime_fermat(p, 100) or not is_prime_fermat(q, 100):
        print("\nThe number {} is NOT a product of two prime numbers!\n".format(n))
        sys.exit(0)
    return p, q

if len(sys.argv) != 3 or int(sys.argv[1]) < 3:
    print("\nSyntax: {} <positive_integer_number> <integer_to_encrypt>\n".format(sys.argv[0]))
    sys.exit(0)

# Need to increase recursion limit because of expm function. Tested with up to 1024-bits keys. Need to increase further to work with larger keys.
sys.setrecursionlimit(3000)

number_of_bits = int(sys.argv[1])
plain_text = int(sys.argv[2])
fermat_rounds = 100

if (plain_text.bit_length()//2 > number_of_bits-1):
    print("\nThe number {} is a {}-bits number. The key lenght (first parameter) should be {} or more \n".format(plain_text, plain_text.bit_length(), int((plain_text.bit_length()/2))+1))
    sys.exit(0)

p = generate_possible_prime_number(number_of_bits, fermat_rounds)
q = generate_possible_prime_number(number_of_bits, fermat_rounds)

print("\nGenerated prime number with {}-bits (p): {}".format(number_of_bits,p))
print("Generated prime number with {}-bits (q): {}".format(number_of_bits,q))

n,e,d = rsaKey(p,q)
#print ("(n,e,d) = ",n,e,d)

publicKey = (n, e)
privateKey = (n, d)
print("\nPublic key:", publicKey)
print("Private key:", privateKey)

c = rsaEnc(n,e,plain_text)
print ("\nCiphertext:", c)
m = rsaDec(n,d,c)
print ("\n==> Plaintext message decrypted using traditional RSA algorithm:", m)
m = rsaDecCRT(c,p,q,d)
print ("\n==> Plaintext message decrypted using Chinese Remainder Theory RSA algorithm:", m)

print ("\n*** Decrypting using ecrack... ***")
print ("\n*** This may take a while to complete depending on the key size. It starts to become slower with keys greater than 44-bits ***")
print ("\n*** Key size used: {}-bits ***".format(number_of_bits))

m = ecrack(n,e,c)
print ("\n==> Plaintext message decrypted using ecrack:", m)
print ("\n")