#!/bin/python3
# -*- coding: utf-8 -*-

'''Tests'''

##-Import
try:
    from base import *
    from arithmetic import *
    from RSA_attacks import *
    from RSA import *
    import test_attacks

except ModuleNotFoundError:
    from modules.base import *
    from modules.arithmetic import *
    from modules.RSA_attacks import *
    from modules.RSA import *
    import modules.test_attacks as test_attacks

from datetime import datetime as dt


##-Test function
def tester(func_name, assertion):
    '''Print what is tested and fail if the assertion failed.'''

    if assertion:
        print(f'Testing {func_name}: passed')
        return True

    else:
        print(f'Testing {func_name}: failed')
        raise AssertionError


##-Base
def test_base():
    tester(
        'base: split',
        split('azertyuiopqsdfghjklmwxcvbn', 3) == ['aze', 'rty', 'uio', 'pqs', 'dfg', 'hjk', 'lmw', 'xcv', 'bn']
    )
    tester(
        'base: split',
        split('azertyuiopqsdfghjklmwxcvbn', 3, '0') == ['aze', 'rty', 'uio', 'pqs', 'dfg', 'hjk', 'lmw', 'xcv', 'bn0']
    )


##-Arithmetic
def test_arith(size=2048):
    tester(
        'arithmetic: mult_inverse',
        [mult_inverse(k, 7) for k in range(1, 7)] == [1, 4, 5, 2, 3, 6]
    )
    tester(
        'arithmetic: max_parity',
        max_parity(256) == (8, 1) and max_parity(123) == (0, 123) and max_parity(8 * 5) == (3, 5)
    )
    tester(
        'arithmetic: isSurelyPrime',
        (not isSurelyPrime(1)) and isSurelyPrime(2) and isSurelyPrime(11) and isSurelyPrime(97) and (not isSurelyPrime(561))
    )
    tester(
        'arithmetic: iroot',
        iroot(2, 2) == 1 and iroot(27, 3) == 3
    )
    print('Testing fermat_factor :')
    tester(
        'arithmetic: fermat_factor',
        test_attacks.test_fermat_factor(size, size // 4)
    )


##-RSA
def test_OAEP(size=2048):
    '''
    Test the OAEP padding scheme.

    - size : the RSA key's size. The OAEP size is `size // 8 - 1`.
    '''

    # Using the LICENCE file as test file
    try:
        with open('LICENCE') as f:
            m = f.read()

    except FileNotFoundError:
        with open('../LICENCE') as f:
            m = f.read()

    C = OAEP(size // 8 - 1)
    e = C.encode(m)

    tester('RSA: OAEP', m.encode() == C.decode(e))


def test_RSA(k=None, pad='raw', size=2048):
    '''Test RSA encryption / decryption'''

    print(f'Testing RSA (padding : {pad}).')

    if k is None:
        print('Generating a key ...', end=' ')
        k = RsaKey()
        k.new(size=size)
        print('Done.')

    else:
        size = k.size

    C = RSA(k, pad)

    if pad.lower() == 'int':
        m = randint(0, k.n - 1)

    else:
        print('Reading file ...', end=' ')
        # Using the LICENCE file as test file
        try:
            with open('LICENCE') as f:
                m = f.read()

        except FileNotFoundError:
            with open('../LICENCE') as f:
                m = f.read()

        print('Done.')

    print('Encrypting ...', end=' ')
    enc = C.encrypt(m)
    print('Done.\nDecrypting ...', end=' ')
    dec = C.decrypt(enc)

    if pad.lower() == 'oaep':
        # print(dec)
        dec = dec.decode()

    print('Done.')

    tester(f'RSA: RSA (padding : {pad})', dec == m)


##-Run tests function
def run_tests(size=2048):
    '''Run all the tests'''

    t0 = dt.now()
    test_base()
    print(f'\n--- {dt.now() - t0}s elapsed.\n')
    test_arith(size=size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')

    test_OAEP(size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')

    test_RSA(pad='int', size=size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')
    test_RSA(pad='raw', size=size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')
    test_RSA(pad='oaep', size=size)
    print(f'\n--- {dt.now() - t0}s elapsed.\n')

    print('All tests passed.') #Otherwise the function `tester` in the tests would have raised an AssertionError.


##-Main
if __name__ == '__main__':
    from sys import argv
    from sys import exit as sysexit

    if len(argv) == 1:
        size = 2048

    else:
        try:
            size = int(argv[1])

        except:
            print(f'Wrong argument at position 1 : should be the RSA key size (in bits).\nExample : "{argv[0]} 2048".')
            sysexit()

    run_tests(size=size)
