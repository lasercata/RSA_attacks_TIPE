#!/bin/python3
# -*- coding: utf-8 -*-

'''Implementation of RSA attacks'''

##-Imports
try:
    from arithmetic import *
    import RSA

except ModuleNotFoundError:
    from modules.arithmetic import *
    import modules.RSA as RSA

import math
from random import randint

from datetime import datetime as dt


##-Elementary attacks
#------Elementary attacks
#---Factor modulus with private key
def factor_with_private(e, d, n, max_tries=None):
    '''
    Factor modulus n using public and private exponent e and d.
    
    - max_tries : stop after `max_tries` tries if not found before. If None, don't stop until found.
    '''

    k = e*d - 1
    t, r = max_parity(k) # k = 2^t * r, r is odd.

    i = 0
    while True:
        g = 0
        while math.gcd(g, n) != 1: # find a g in (Z/nZ)^*
            g = randint(2, n - 1)
        
        for j in range(t, 1, -1): # Try with g^(k / 2^j)
            x = pow(g, k // (2**j), n)
            y = math.gcd(x - 1, n)

            if n % y == 0 and (y not in (1, n)):
                return y, n//y

        if max_tries != None:
            i += 1
            if i >= max_tries:
                return None


#---Common modulus
def common_modulus(N, e, d, e1):
    '''
    Entry :
        - N  : the common modulus ;
        - e  : the known public exponent ;
        - d  : the known private exponent ;
        - e1 : public exponent associated to the wanted private exponent.
    
    Calculate d1 the private exponent associated to e1.
    '''

    p, q = factor_with_private(e, d, N)
    phi = (p - 1) * (q - 1)

    return mult_inverse(e1, phi)


#---Multiplicative attack
def multiplicative_attack(m_, r, n):
    '''
    Uses the fact that the product of two ciphertexts is equal to the ciphertext of the product.

    We have c = m^e [n] and we want m.
    We ask for the decryption of c_ = c * r^e [n] (m_).

    - m_ : the decryption of c_ = c * r^e [n] ;
    - r  : the number used to obfuscate the initial message ;
    - n  : the modulus.
    '''

    inv_r = mult_inverse(r, n)

    return (m_ * inv_r) % n


#------Large message (close to n)
def large_message(c, e, n):
    '''
    Return the decryption of c using the method from Hinek's paper (cacr2004).
    In order for this attack to work, we need to have
        n - n^(1/e) < m < n
    Then we have :
        m = n - (-c % n)^(1/e).
    
    Arguments :
        - c : the encryption of m : c = m^e [n] ;
        - e : the public exponent ;
        - n : the RSA modulus.
    '''
    
    return n - iroot(-c % n, e)


##-Hastad
#---Hastad (same message)
def _hastad(e, enc_msg_lst, mod_lst):
    '''
    Return (me, e, M). The decrypted message is `iroot(me, e)` or `large_message(me, e, M)` (if the message was very long).
    
    - e           : the common public exponent ;
    - enc_msg_lst : the list of the encrypted messages ;
    - mod_lst     : the list of modulus.
    
    The lists `enc_msg_lst` and `mod_lst` should have the same length.
    '''

    M = 1
    for k in mod_lst:
        M *= k
    
    me = sum(enc_msg_lst[k] * (M // mod_lst[k]) * mult_inverse(M // mod_lst[k], mod_lst[k]) for k in range(len(mod_lst))) % M

    return (me, e, M)


def hastad(e, enc_msg_lst, mod_lst):
    '''
    Return the decrypted message.
    
    - e           : the common public exponent ;
    - enc_msg_lst : the list of the encrypted messages ;
    - mod_lst     : the list of modulus.
    
    The lists `enc_msg_lst` and `mod_lst` should have the same length.
    '''

    me, e = _hastad(e, enc_msg_lst, mod_lst)[:-1]

    return iroot(me, e)


def hastad_large_message(e, enc_msg_lst, mod_lst):
    '''
    Return the decrypted message.
    
    - e           : the common public exponent ;
    - enc_msg_lst : the list of the encrypted messages ;
    - mod_lst     : the list of modulus.
    
    The lists `enc_msg_lst` and `mod_lst` should have the same length.
    '''

    me, e, M = _hastad(e, enc_msg_lst, mod_lst)

    return large_message(me, e, M)


##-Wiener's attack
def factor_with_phi(n, phi):
    '''
    Return (p, q) such that n = pq, if possible. Otherwise, raise a ValueError
    
    - n   : the RSA modulus ;
    - phi : the Euler totien of n : phi = (p - 1)(q - 1).
    
    It solve the quadratic
        x^2 - (n - phi + 1)x + n = 0
    '''
    
    delta = (n - phi + 1)**2 - 4*n
    
    if delta < 0:
        raise ValueError('Wrong modulus or wrong phi.')
    
    p = (n - phi + 1 - isqrt(delta)) // 2
    q = (n - phi + 1 + isqrt(delta)) // 2
    
    if p * q != n:
        raise ValueError('Wrong modulus or wrong phi.')
    
    return p, q


def wiener(e, n):
    '''
    Run Wiener's attack on the public key (e, n).
    Return a private RsaKey object.

    Can factor the key if the private exponent d is such that
        1 < d < n^(1/4) / 3
        or
        phi - n^(1/4)/sqrt(6) < d < phi
    
    - e : the public exponent ;
    - n : the modulus.
    '''
    
    #---Calculate the continued fraction of e/n
    e_n_frac = get_continued_fraction(e, n)
    
    #---Calculate the convergents
    k_, d_ = e_n_frac.get_convergents()
    
    #---Compute phi to check correctness
    for i in range(1, len(k_) - 2):
        phi = (e * d_[i] - 1) // k_[i]
        phi2 = (e * d_[i] + 1) // k_[i] #With large private exponent.
        
        try:
            p, q = factor_with_phi(n, phi)
        
        except ValueError:
            try:
                p2, q2 = factor_with_phi(n, phi2)

            except ValueError:
                continue

            else: #Correct factorisation with p2, q2
                key = RSA.RsaKey(e, phi2 - d_[i], n, phi2, p2, q2)
                return key
        
        else: #Correct factorisation with p, q
            key = RSA.RsaKey(e, d_[i], n, phi, p, q)
            return key
    
    raise ValueError('The attack failed with this key')

