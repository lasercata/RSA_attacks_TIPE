#!/bin/python3
# -*- coding: utf-8 -*-

'''Tests for RSA attacks'''

##-imports
try:
    from RSA_attacks import *
    from base import str_diff, int_to_bytes, bytes_to_int

except ModuleNotFoundError:
    from modules.RSA_attacks import *
    from modules.base import str_diff, int_to_bytes, bytes_to_int

from secrets import randbits
from random import randint

##-Fermat factorisation
def test_fermat_factor(size=2048, dist=512):
    '''
    Tests the Fermat factorisation : generates two primes p, q and test the algorithm on it.

    - size : the size of the modulus to generate in bits, i.e of p*q ;
    - dist : the bit size of |p - q| ;
    '''

    print('Prime generation ...')
    t0 = dt.now()

    p = 1
    while not isSurelyPrime(p):
        p = randbits(size // 2)

    q = p + 2**dist
    while not isSurelyPrime(q):
        q +=1

    print(f'Generation done in {dt.now() - t0}s.\np : {round(math.log2(p), 2)} bits\nq : {round(math.log2(q), 2)} bits\n|p - q| : {round(math.log2(q - p), 2)} bits\n2 * |p - q|^(1/4) : {round(math.log2(2 * iroot(p * q, 4)), 2)}')

    b = q - p <= 2 * iroot(p * q, 4)

    print('\nFactorisation ...')
    t1 = dt.now()
    a, b = fermat_factor(p * q)
    print(f'Factorisation done in {dt.now() - t1}s.')

    if a * b != p * q:
        print('Factorisation failed : the product of the result is not p * q.')
        return False

    if not (p in (a, b) and q in (a, b)):
        print('Factorisation failed : p or q not in the result.')
        return False

    print('Good factorisation.')

    return True


##-Modulus factorisation
def test_mod_fact(size=2048):
    print('Key generation ...')
    t0 = dt.now()
    key = RSA.RsaKey()
    key.new(size)
    print(f'Generation done in {dt.now() - t0}s.')

    t1 = dt.now()
    try:
        p, q = factor_with_private(key.e, key.d, key.n)

    except TypeError:
        print('not found !')
        return False

    else:
        print('Found in {}.\nCorrect : n == pq : {}, key.p in (p, q) : {}'.format(dt.now() - t1, key.n == p*q, key.p in (p, q)))
        return True

        # for k in (key.p, key.q, p, q):
        #     print(k)

##-Common modulus
def test_common_mod(size=2048):
    print('Key generation ...')
    t0 = dt.now()
    key = RSA.RsaKey()
    key.new(size)
    print(f'Generation done in {dt.now() - t0}s.')

    t1 = dt.now()
    e1 = 0
    while math.gcd(e1, key.phi) != 1:
        e1 = randint(max(key.p, key.q), key.phi)

    print(f'Generation of e1 done in {dt.now() - t1}s.')

    t2 = dt.now()
    d1 = mult_inverse(e1, key.phi)
    if common_modulus(key.n, key.e, key.d, e1) == d1:
        print(f'Attack succeeded : private exposant recovered.\nDone in {dt.now() - t2}s.')
        return True
    else:
        print(f'Attack failed : private exposant NOT recovered.\nDone in {dt.now() - t2}s.')
        return False


##-Test Multiplicative attack
def test_multiplicative_attack_one_block(m=None, size=2048):
    '''
    Test multiplicative_attack.

    - m    : the message (int). If None, generates a random one ;
    - size : the RSA key size.
    '''

    t0 = dt.now()
    print('Key generation ...')
    key = RSA.RsaKey()
    key.new(size)

    n = key.n
    e = key.e
    d = key.d

    print(f'Done in {dt.now() - t0}s')

    if m == None:
        m = randint(1, n - 1)

    c = pow(m, e, n)

    t1 = dt.now()
    print('Running the attack ...')
    r = randint(2, n - 1)

    if math.gcd(r, n) != 1: # To ensure that r is inversible modulo n
        p = math.gcd(r, n)
        q = n // p
        print(f'We accidentally factorized n ...\nn = {n}\np = {p}\nq = {q}.\nn == p*q : {n == p * q}.')
        return n == p * q

    c_ = (c * pow(r, e, n)) % n #obfuscated encrypted message
    m_ = pow(c_, d, n) #The inoffensive looking message (obfuscated) gently decrypted by Alice

    recov_m = multiplicative_attack(m_, r, n)

    print(f'Attack done in {dt.now() - t1}s.')

    if recov_m == m:
        print('Attack successful')
        return True

    else:
        print('Attack failed')
        return False


def test_multiplicative_attack(m=None, size=2048):
    '''
    Test multiplicative_attack.

    - m    : the message (int). If None, generates a random one ;
    - size : the RSA key size.
    '''

    t0 = dt.now()
    print('Key generation ...')
    key = RSA.RsaKey()
    key.new(size)

    n = key.n
    e = key.e
    d = key.d

    print(f'Done in {dt.now() - t0}s')

    if m == None:
        m = randint(1, n - 1)

    E = RSA.OAEP(key.size // 8 - 1)
    m_e = [bytes_to_int(k) for k in E.encode(int_to_bytes(m))] #message encoded in blocks
    enc_lst = [pow(k, e, n) for k in m_e] #The ciphertexts

    t1 = dt.now()
    print('Running the attack ...')
    r_lst = [randint(2, n - 1) for k in range(len(m_e))] #choose one r per block

    for r in r_lst:
        if math.gcd(r, n) != 1: # To ensure that all r are inversible modulo n
            p = math.gcd(r, n)
            q = n // p

            print(f'We accidentally factorized n ...\nn = {n}\np = {p}\nq = {q}.\nn == p*q : {n == p * q}.')

            return n == p * q

    enc_lst_r = [(c_k * pow(r_k, e, n)) % n for (c_k, r_k) in zip(enc_lst, r_lst)] #List of obfuscated encrypted messages

    dec_lst = [pow(k, d, n) for k in enc_lst_r] #The inoffensive looking messages (obfuscated) gently decrypted by Alice

    recov_lst = [multiplicative_attack(m_k, r_k, n) for (m_k, r_k) in zip(dec_lst, r_lst)]

    decoded = E.decode([int_to_bytes(k) for k in recov_lst])

    print(f'Attack done in {dt.now() - t1}s.')

    if bytes_to_int(decoded) == m:
        print('Attack successful')
        return True

    else:
        print('Attack failed')
        return False


##-Test large positive numbers
def test_large_message(e=3, size=2048, verbose=False):
    '''
    Cf cacr2004 (Hinek) paper.
    Generates an RSA key, and a message m such that n - n^(1/e) < m < n
    Then encrypt it : c = m^e [n]
    It is possible to recover the message :
        m = n - (-c % n)^(1/e)
    '''

    print('Generating RSA key ...')
    t0 = dt.now()

    k = RSA.RsaKey(e = e)
    k.new(size)
    print(f'Generation done in {dt.now() - t0}s.')

    print('Generating message and encrypting it ...')
    t1 = dt.now()
    m = randint(k.n - iroot(k.n, e), k.n)
    c = pow(m, e, k.n)
    print(f'Done in {dt.now() - t1}s.')

    print('Recovering the message ...')
    t2 = dt.now()
    m_recov = large_message(c, k.e, k.n)
    print(f'Message recovered in {dt.now() - t2}s.')

    if str_diff(str(m), str(m_recov), verbose=verbose, max_len=-1):
        print(f'Attack successful. Done in {dt.now() - t0}s.')
        return True

    else:
        print(f'Attack failed. Time elapsed : {dt.now() - t0}s.')
        return False


##-Hastad
def test_hastad(msg = 'testing', e=3, size=2048, nb_eq=None, try_large=False):
    '''
    Tests the `hastad` function.

    - msg       : the message that will be encrypted with RSA and be recovered ;
    - e         : the public exponent used for all the keys ;
    - size      : the size of the modulus ;
    - nb_eq     : the number of equations. If None, calculate the right number using the message ;
    - try_large : bool indicating if trying to break the message using hastad_large_message.
    '''

    msg = int(''.join(format(ord(k), '03') for k in msg)) #testing -> 116101115116105110103

    n = math.ceil(e * math.log2(msg) / size)
    print(f'Number of equations actually needed to recover the message : {n}.')

    if nb_eq == None:
        nb_eq = n

    keys = [RSA.RsaKey(e=e) for k in range(nb_eq)]

    print(f'\nKey generation for Hastad\'s attack ({size} bits, {nb_eq} keys) ...')
    t0 = dt.now()
    for k in range(nb_eq):
        t1 = dt.now()
        keys[k].new(size)
        print(f'{k + 1}/{nb_eq} generated in {dt.now() - t1}s.')

    print(f'Done in {dt.now() - t0}s.')

    mod_lst = [keys[k].n for k in range(nb_eq)]
    ciphers = [RSA.RSA(keys[k], 'int') for k in range(nb_eq)]
    enc_lst = [ciphers[k].encrypt(msg) for k in range(nb_eq)]

    print('\nHastad attack ...')
    t2 = dt.now()
    ret = hastad(e, enc_lst, mod_lst)
    print(f'Attack done in {dt.now() - t2}s.')

    dec_out = ''.join([chr(int(str(ret)[3*k : 3*k + 3])) for k in range(len(str(ret)) // 3)])

    if msg != ret and try_large:
        # This can't work because no message can fit in [M - M^(1/e) ; M] : they would need to have exactly len(str(M))/k = len(str(M - iroot(M, e)))/k characters (where k is defined with the encoding used (here it is k = 3)) so we need that k divide len(str(M)) (thus that way it is possible to find an int of this length that will thus maybe correspond to an encoded message).

        print('Attack failed, trying to use the large number way ...')

        M = 1
        for k in range(nb_eq):
            M *= keys[k].n

        print(f'Is the condition good for large number attack ? : {M - iroot(M, e) <= msg <= M}')
        if M - iroot(M, e) > msg:
            print('Message is too small for the large message attack.')

        elif msg > M:
            print('Message is too large for the large message attack.')

        t3 = dt.now()
        ret2 = hastad_large_message(e, enc_lst, mod_lst)
        print(f'Attack done in {dt.now() - t3}s.')

        return str_diff(msg, ret2)

    return str_diff(msg, ret)

    #print(f'\nDecoded output :\n{dec_out}')

#-Test message size limit
def test_hastad_message_size(msg_size=100, e=3, size=2048):
    '''
    Test the number size with the number of equations

    - msg_size : the length of the message ;
    - e        : the public exponent used for all the keys ;
    - size     : the size of the modulus.
    '''

    msg = ''.join([chr(randint(65, 122)) for k in range(msg_size)]) #Random chars
    msg = int(''.join(format(ord(k), '03') for k in msg)) #Encoding the message

    n = math.ceil(e * math.log2(msg) / size)
    print(f'Number of equations theoretically needed to recover the message : {n}.')

    keys = [RSA.RsaKey(e=e) for k in range(n)]

    print(f'\nKey generation for Hastad\'s attack ({size} bits) ...')
    t0 = dt.now()
    for k in range(n):
        t1 = dt.now()
        keys[k].new(size)
        print(f'{k + 1}/{n} generated in {dt.now() - t1}s.')

    print(f'Done in {dt.now() - t0}s.')

    mod_lst = [keys[k].n for k in range(n)]
    ciphers = [RSA.RSA(keys[k], 'int') for k in range(n)]
    enc_lst = [ciphers[k].encrypt(msg) for k in range(n)]

    print(f'\nHastad attack with {n} equations ...')
    t2 = dt.now()
    ret1 = hastad(e, enc_lst, mod_lst)
    print(f'Attack done in {dt.now() - t2}s.')

    if msg == ret1:
        print('Attack succeeded : message correctly recovered.')

    else:
        print('Attack failed : message NOT correctly recovered.')
        return False

    if n - 1 == 0:
        print('\nNot trying to with less equations than one.')
        return True

    print(f'\nHastad attack with {n - 1} equations ...')
    t3 = dt.now()
    ret2 = hastad(e, enc_lst[:-1], mod_lst[:-1])
    print(f'Attack done in {dt.now() - t3}s.')

    if msg == ret2:
        print('Attack succeeded : message correctly recovered. So the limit is NOT correct.')
        return False

    else:
        print('Attack failed : message not correctly recovered. So the limit is correct.')
        return True


def test_hastad_large_message(e=3, size=2048, less=0):
    '''
    Tests the `hastad` function, with large message (see Hinek's paper).

    - e    : the public exponent used for all the keys ;
    - size : the size of the modulus ;
    - less : the number of equations to remove.

    But the problem with this is that it generates the message after having M, which is not how it would be in real life.
    '''

    keys = [RSA.RsaKey(e=e) for k in range(e)]

    print(f'\nKey generation for Hastad\'s attack ({size} bits) ...')
    t0 = dt.now()
    for k in range(e):
        t1 = dt.now()
        keys[k].new(size)
        print(f'{k + 1}/{e} generated in {dt.now() - t1}s.')

    print(f'Done in {dt.now() - t0}s.')

    M = 1
    for k in range(e):
        M *= keys[k].n

    msg = randint(M - iroot(M, e), M)
    print('len(str(msg)) :', len(str(msg)), 'log2(M) :', math.log2(M))
    print(f'Number of equations actually needed to recover the message (without large message idea) : {math.ceil(e * math.log2(msg) / size)}.')
    #print(f'msg : {msg}')

    mod_lst = [keys[k].n for k in range(e - less)]
    ciphers = [RSA.RSA(keys[k], 'int') for k in range(e - less)]
    enc_lst = [ciphers[k].encrypt(msg) for k in range(e - less)]

    print('\nHastad attack ...')
    t2 = dt.now()
    ret = hastad_large_message(e, enc_lst, mod_lst)
    print(f'Attack done in {dt.now() - t2}s.')

    if str_diff(str(msg), str(ret)):
        return True

    else:
        return False


##-Wiener
def test_wiener(size=2048, large=False, not_in_good_condition=False):
    '''
    Test Wiener's attack.

    - size                  : The RSA key size ;
    - large                 : if True, generates a large private exponent ;
    - not_in_good_condition : Do not try to generate a key that is breakable with this attack.
    '''

    key = RSA.RsaKey()

    print(f'Key generation for Wiener\'s attack ({size} bits) ...')
    t0 = dt.now()
    if not_in_good_condition:
        key.new()

    elif large:
        key.new_wiener_large(size)

    else:
        key.new_wiener(size)

    print(f'Key generated in {dt.now() - t0}s.')

    pb = key.public()

    t1 = dt.now()
    try:
        recovered_key = wiener(pb.e, pb.n)

    except ValueError as err:
        print(f'Wiener\'s attack finished in {dt.now() - t1}s.')
        print(err)
        return False

    print(f'Wiener\'s attack finished in {dt.now() - t1}s.')

    if recovered_key == key:
        print('Correct result !')
        return True

    else:
        print('Incorrect result !')
        return False

if __name__ == '__main__':
    # test_wiener(large=True)
    test_multiplicative_attack()

