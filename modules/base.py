#!/bin/python3
# -*- coding: utf-8 -*-

'''Miscellaneous and useful functions'''

##-Imports
import hashlib


##-Split function
def split(txt, size, pad_=None):
    '''
    Return a list representing txt by groups of size `size`.

    - txt  : the text to split ;
    - size : the block size ;
    - pad_  : if not None, pad the last block with `pad_` to be `size`length (adding to the end).
    '''

    l = []

    for k in range(len(txt) // size + 1):
        p = txt[k*size : (k+1)*size]

        if p in ('', b''):
            break

        if pad_ != None:
            p = pad(p, size, pad_)

        l.append(p)

    return l


def pad(txt, size, pad=' ', end=True):
    '''
    Pad `txt` to make it `size` long.
    If len(txt) > size, it just returns `txt`.

    - txt  : the string to pad ;
    - size : the final wanted size ;
    - pad  : the character to use to pad ;
    - end  : if True, add to the end, otherwise add to the beginning.
    '''

    while len(txt) < size:
        if end:
            txt += pad

        else:
            txt = pad + txt

    return txt


##-Mask generation function
# From https://en.wikipedia.org/wiki/Mask_generation_function
def i2osp(integer: int, size: int = 4) -> str:
    return int.to_bytes(integer % 256**size, size, 'big')

def mgf1(input_str: bytes, length: int, hash_func=hashlib.sha256) -> str:
    '''Mask generation function.'''

    counter = 0
    output = b''
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1

    return output[:length]


##-Xor
def xor(s1, s2):
    '''Return s1 xored with s2 bit per bit.'''

    if (len(s1) != len(s2)):
        raise ValueError('Strings are not of the same length.')

    if type(s1) != bytes:
        s1 = s1.encode()

    if type(s2) != bytes:
        s2 = s2.encode()

    l = [i ^ j for i, j in zip(list(s1), list(s2))]

    return bytes(l)


##-Int and bytes
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'little')

def bytes_to_int(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'little')


##-Other
def str_diff(s1, s2, verbose=True, max_len=80):
    '''
    Show difference between strings (or numbers) s1 and s2. Return s1 == s2.

    - s1      : input string to compare ;
    - s2      : output string to compare ;
    - verbose : if True, show input and output message and where they differ if so ;
    - max_len : don't show messages if their length is more than max_len. Default is 80. If negative, always show them.
    '''

    s1 = str(s1)
    s2 = str(s2)

    if verbose:
        if len(s1) <= max_len or max_len == -1:
            print(f'\nEntry message : {s1}')
            print(f'Output        : {s2}')

        for k in range(len(s1)):
            if s1[k] != s2[k]:
                if len(s1) <= max_len or max_len == -1:
                    print(' '*(len('Output        : ') + k) + '^')

                print('Input and output differ from position {}.'.format(k))

                return False

        print('Input and output are identical.')

    return s1 == s2


##-Testing
if __name__ == '__main__':
    msg = input('msg\n>').encode()

    print(mgf1(msg, 10).hex())
    print(xor('test', 'abcd'))

