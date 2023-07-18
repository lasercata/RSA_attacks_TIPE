#!/bin/python3
# -*- coding: utf-8 -*-

'''Implementation of RSA cipher and key management'''

##-Imports
try:
    from arithmetic import *
    from base import *

except ModuleNotFoundError:
    from modules.arithmetic import *
    from modules.base import *

from secrets import randbits
from random import randint, randbytes
import math

import base64

##-RsaKeys
class RsaKey:
    '''RSA key object'''

    def __init__(self, e=None, d=None, n=None, phi=None, p=None, q=None):
        '''
        - e : public exponent
        - d : private exponent
        - n : modulus
        - p, q : primes that verify pq = n
        - phi = (p - 1)(q - 1)
        '''

        self.e = e
        self.d = d
        self.n = n
        self.phi = phi
        self.p = p
        self.q = q

        self.is_private = self.d != None

        if self.is_private:
            if self.q < self.q:
                self.p = q
                self.q = p

        self.pb = (e, n)
        if self.is_private:
            self.pv = (d, n)

        self.size = None
    
    def __repr__(self):
        if self.is_private:
            return f'RsaKey private key :\n\tsize : {self.size}\n\te : {self.e}\n\td : {self.d}\n\tn : {self.n}\n\tphi : {self.phi}\n\tp : {self.p}\n\tq : {self.q}'
        
        else:
            return f'RsaKey public key :\n\tsize : {self.size}\n\te : {self.e}\n\tn : {self.n}'
    
    
    def __eq__(self, other):
        '''Return True if the key are of the same type (public / private) and have the same values.'''
        
        ret = self.is_private == other.is_private

        if not ret:
            return False
        
        if self.is_private:
            ret = ret and (
                self.e == other.e and
                self.d == other.d and
                self.n == other.n and
                self.phi == other.phi
            )
            
            ret = ret and ((self.p == other.p and self.q == other.q) or (self.q == other.p and self.p == other.q))
        
        else:
            ret = ret and (
                self.e == other.e and
                self.n == other.d
            )
        
        return ret
    
    
    def public(self):
        '''Return the public key associated to self in an other RsaKey object.'''
        
        k = RsaKey(e=self.e, n=self.n)
        k.size = self.size
        return k
    

    def _gen_nb(self, size=2048, wiener=False):
        '''
        Generates p, q, and set attributes p, q, phi, n, size.
        
        - size   : the bit size of n ;
        - wiener : If True, generates p, q prime such that q < p < 2q.
        '''

        self.p, self.q = 1, 1

        while not isSurelyPrime(self.q):
            self.q = randbits(size // 2)
        
        while not (isSurelyPrime(self.p) and ((wiener and self.q < self.p < 2 * self.q) or (not wiener))):
            self.p = randbits(size // 2)

        self.phi = (self.p - 1) * (self.q - 1)
        self.n = self.p * self.q

        self.size = size


    def new(self, size=2048):
        '''
        Generate RSA keys of size `size` bits.
        If self.e != None, it keeps it (and ensures that gcd(phi, e) = 1).

        - size : the key size, in bits.
        '''

        self._gen_nb(size)

        while self.e != None and math.gcd(self.e, self.phi) != 1:
            self._gen_nb(size)

        if self.e == None:
            self.e = 0
            while math.gcd(self.e, self.phi) != 1:
                self.e = randint(max(self.p, self.q), self.phi)
        
        elif math.gcd(self.e, self.phi) != 1: #Not possible !
            raise ValueError('RsaKey: new: error: gcd(self.e, self.phi) != 1')
        
        self.d = mult_inverse(self.e, self.phi)

        self.is_private = True

        self.pb = (self.e, self.n)
        self.pv = (self.d, self.n)

        self.size = size
    
    
    def new_wiener(self, size=2048):
        '''
        Generate RSA keys of size `size` bits.
        If self.e != None, it does NOT keeps it.
        These key are generated so that the Wiener's attack is possible on them.
        
        - size : the key size, in bits.
        '''
        
        self._gen_nb(size, wiener=True)
        
        self.d = 0
        while math.gcd(self.d, self.phi) != 1:
            self.d = randint(1, math.floor(isqrt(isqrt(self.n))/3))
        
        self.e = mult_inverse(self.d, self.phi)
        
        self.is_private = True

        self.pb = (self.e, self.n)
        self.pv = (self.d, self.n)

        self.size = size


    def new_wiener_large(self, size=2048, only_large=True):
        '''
        Same as `self.new_wiener`, but `d` can be very large.

        - size       : the RSA key size ;
        - only_large : if False, d can be small, or large, and otherwise, d is large.
        '''

        self._gen_nb(size, wiener=True)

        self.d = 0
        while math.gcd(self.d, self.phi) != 1:
            if only_large:
                #ceil(sqrt(6)) = 3
                self.d = randint(int(self.phi - iroot(self.n, 4) // 3), self.phi)

            else:
                self.d = randint(1, self.phi)
                if iroot(self.n, 4) / 3 < self.d or self.d < self.phi - iroot(self.n, 4) / math.sqrt(6):
                    self.d = 0 #go to the next iteration

        self.e = mult_inverse(self.d, self.phi)
        self.is_private = True
        self.pb = (self.e, self.n)
        self.pv = (self.d, self.n)

        self.size = size



##-Padding
class OAEP:
    '''Class implementing OAEP padding'''

    def __init__(self, block_size, k0=None, k1=0):
        '''
        Initiate OAEP class.
        
        - block_size   :    the bit size of each block ;
        - k0           :    integer (number of bits in the random part). If None, it is set to block_size // 8 ;
        - k1           :    integer such that len(block) + k0 + k1 = block_size. Default is 0.
        '''

        self.block_size = block_size #n

        if k0 == None:
            k0 = block_size // 8

        self.k0 = k0
        self.k1 = k1
    
    
    def _encode_block(self, block):
        '''
        Encode a block.
        
        - block : an n - k0 - k1 long bytes string.
        '''

        #---Add k1 \0 to block
        block += (b'\0')*self.k1
        
        #---Generate r, a k0 bits random string
        r = randbytes(self.k0)

        X = xor(block, mgf1(r, self.block_size - self.k0))

        Y = xor(r, mgf1(X, self.k0))

        return X + Y
    

    def encode(self, txt):
        '''
        Encode txt
        
        Entry :
            - txt : the string text to encode.
        
        Output :
            bytes list
        '''

        if type(txt) != bytes:
            txt = txt.encode()
        
        #---Cut message in blocks of size n - k0 - k1
        blocks = []
        l = self.block_size - self.k0 - self.k1

        blocks = split(txt, l, pad_=b'\0')

        #---Encode blocks
        enc = []
        for k in blocks:
            enc.append(self._encode_block(k))
        
        return enc
    

    def _decode_block(self, block):
        '''Decode a block encoded with self._encode_block.'''

        X = block[:self.block_size - self.k0]
        Y = block[-self.k0:]

        r = xor(Y, mgf1(X, self.k0))

        txt = xor(X, mgf1(r, self.block_size - self.k0))

        while txt[-1] == 0: #Remove padding
            txt = txt[:-1]

        return txt


    def decode(self, enc):
        '''
        Decode a text encoded with self.encode.
        
        - enc : a list of bytes encoded blocks.
        '''

        txt = b''

        for k in enc:
            txt += self._decode_block(k)
        
        return txt



#-RSA
class RSA:
    '''RSA cipher'''

    def __init__(self, key, padding, block_size=None):
        '''
        - key        : a RsaKey object ;
        - padding    : the padding to use. Possible values are :
            'int' : msg is an int, return an int ;
            'raw' : msg is a string, simply cut it in blocks ;
            'oaep' : OAEP padding ;
        - block_size : the size of encryption blocks. If None, it is set to `key.size // 8 - 1`.
        '''

        self.pb = key.pb
        if key.is_private:
            self.pv = key.pv
        
        self.is_private = key.is_private

        if padding.lower() not in ('int', 'raw', 'oaep'):
            raise ValueError('RSA: padding not recognized.')
        
        self.pad = padding.lower()

        if block_size == None:
            self.block_size = key.size // 8 - 1

        else:
            self.block_size = block_size
    

    def encrypt(self, msg):
        '''
        Encrypt `msg` using the key given in init.
        Redirect toward the right method (using the good padding).
        
        - msg     : The string to encrypt.
        '''

        if self.pad == 'int':
            return self._encrypt_int(msg)
        
        elif self.pad == 'raw':
            return self._encrypt_raw(msg)
        
        else:
            return self._encrypt_oaep(msg)
    
    
    def decrypt(self, msg):
        '''
        Decrypt `msg` using the key given in init, if it is a private one. Otherwise raise a TypeError.
        Redirect toward the right method (using the good padding).
        '''

        if not self.is_private:
            raise TypeError('Can not decrypt using a public key.')

        if self.pad == 'int':
            return self._decrypt_int(msg)
        
        elif self.pad == 'raw':
            return self._decrypt_raw(msg)
        
        else:
            return self._decrypt_oaep(msg)
    

    def _encrypt_int(self, msg):
        '''
        RSA encryption in its simplest form.
        
        - msg : an integer to encrypt.
        '''

        e, n = self.pb

        return pow(msg, e, n)
    

    def _decrypt_int(self, msg):
        '''
        RSA decryption in its simplest form.
        Decrypt `msg` using the key given in init if possible, using the 'int' padding.
        
        - msg : an integer.
        '''
        
        d, n = self.pv

        return pow(msg, d, n)
    

    def _encrypt_raw(self, msg):
        '''
        Encrypt `msg` using the key given in init, using the 'raw' padding.
        
        - msg : The string to encrypt
        '''

        e, n = self.pb

        #---Encode msg
        if type(msg) != bytes:
            msg = msg.encode()

        #---Cut message in blocks
        m_lst = split(msg, self.block_size)
        
        #---Encrypt message
        enc_lst = []
        for k in m_lst:
            enc_lst.append(pow(bytes_to_int(k), e, n))

        return b' '.join([base64.b64encode(int_to_bytes(k)) for k in enc_lst])
    

    def _decrypt_raw(self, msg):
        '''Decrypt `msg` using the key given in init if possible, using the 'raw' padding'''
        
        d, n = self.pv

        enc_lst = [base64.b64decode(k) for k in msg.split(b' ')]

        c_lst = []
        for k in enc_lst:
            c_lst.append(pow(bytes_to_int(k), d, n))
        
        txt = b''
        for k in c_lst:
            txt += int_to_bytes(k)

        return txt.decode()

    
    def _encrypt_oaep(self, msg):
        '''Encrypt `msg` using the key given in init, using the 'oaep' padding.'''

        e, n = self.pb

        if type(msg) != bytes:
            msg = msg.encode()

        #---Padding
        E = OAEP(self.block_size)
        m_lst = E.encode(msg)
        
        #---Encrypt message
        enc_lst = []
        for k in m_lst:
            enc_lst.append(pow(bytes_to_int(k), e, n))
        
        return b' '.join([base64.b64encode(int_to_bytes(k)) for k in enc_lst])

    
    def _decrypt_oaep(self, msg):
        '''Decrypt `msg` using the key given in init if possible, using the 'oaep' padding.'''

        d, n = self.pv

        #---Decrypt
        enc_lst = [base64.b64decode(k) for k in msg.split(b' ')]
        c_lst = []

        for k in enc_lst:
            c_lst.append(pow(bytes_to_int(k), d, n))
        
        #---Decode
        encoded_lst = []
        for k in c_lst:
            encoded_lst.append(pad(int_to_bytes(k), self.block_size, b'\0'))
        
        E = OAEP(self.block_size)

        return E.decode(encoded_lst)


##-Testing
if __name__ == '__main__':
    from tests import test_OAEP, test_RSA, dt
    from sys import argv, exit as sysexit

    if len(argv) == 1:
        size = 2048

    else:
        try:
            size = int(argv[1])

        except:
            print(f'Wrong argument at position 1 : should be the RSA key size (in bits).\nExample : "{argv[0]} 2048".')
            sysexit()

    t0 = dt.now()
    print('Generating a key (for all the tests) ...')
    k = RsaKey()
    k.new(size)
    print('Done.')

    test_OAEP(size // 8 - 1)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')
    test_RSA(k, 'int', size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')
    test_RSA(k, 'raw', size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')
    test_RSA(k, 'oaep', size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')

