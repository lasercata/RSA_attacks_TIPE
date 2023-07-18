#!/bin/python3
# -*- coding: utf-8 -*-

'''Main file running tests on the attacks'''

##-Import
from modules.test_attacks import *

from datetime import datetime as dt
from sys import argv
from sys import exit as sysexit

##-Run tests function
def run_tests(size=2048):
    '''Run the tests defined in the file `test_attacks.py`.'''

    passed = []

    t0 = dt.now()

    try:
        print('Launching tests...')
        print('-' * 16)

        print('1. Testing factorisation of the modulus with the private exponent :')
        passed.append(test_mod_fact(size))
        print('-' * 16)

        print('2. Testing common modulus (finding the private exponent knowing a key set with the same exponent) :')
        passed.append(test_common_mod(size))
        print('-'*16)

        print('3. Testing multiplicative attack :')
        passed.append(test_multiplicative_attack(size))
        print('-'*16)

        print('4. Testing Hastad\'s attack (e = 5) :')
        passed.append(test_hastad(msg='Testing this attack with this message, because a message is needed.', size=size, e=5))
        print('-'*16)

        print('5. Testing Hastad\'s attack, testing the limit number of equations needed (e = 5, random message of length 100 characters) :')
        passed.append(test_hastad_message_size(size=size, e=5))
        print('-'*16)

        print('6. Testing Wiener\'s attack :')
        passed.append(test_wiener(size=size))
        print('-'*16)

        print('7. Testing Wiener\'s attack with a large private exponent :')
        passed.append(test_wiener(size=size, large=True))
        print('-'*16)

        print(f'\nDone in {dt.now() - t0}s.')

    except KeyboardInterrupt:
        print(f'\nStopped. Time elapsed : {dt.now() - t0}s.\nNumber of tests done : {len(passed)}')

    if not False in passed:
        print('\nAll tests passed correctly !')

    else:
        print('\nThe following tests failed :')

        for k, b in enumerate(passed):
            if not b:
                print(f'\t{k + 1}')

##-Run
if __name__ == '__main__':
    if len(argv) == 1:
        size = 2048

    else:
        try:
            size = int(argv[1])

        except:
            print(f'Wrong argument at position 1 : should be the RSA key size (in bits).\nExample : "{argv[0]} 2048".')
            sysexit()

    run_tests(size)
