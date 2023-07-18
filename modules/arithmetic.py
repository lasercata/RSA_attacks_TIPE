#!/bin/python3
# -*- coding: utf-8 -*-

'''Useful arithmetic functions'''

##-Imports
from random import randint
from math import floor, ceil, sqrt, isqrt
from fractions import Fraction
from gmpy2 import is_square


##-Multiplicative inverse
def mult_inverse(a: int, n: int) -> int:
    '''
    Return the multiplicative inverse u of a modulo n.
    u*a = 1 modulo n
    '''

    (old_r, r) = (a, n)
    (old_u, u) = (1, 0)

    while r != 0:
        q = old_r // r
        (old_r, r) = (r, old_r - q*r)
        (old_u, u) = (u, old_u - q*u)

    if old_r > 1:
        raise ValueError(str(a) + ' is not inversible in the ring Z/' + str(n) + 'Z.')

    if old_u < 0:
        return old_u + n

    else:
        return old_u


##-Max parity
def max_parity(n):
    '''return (t, r) such that n = 2^t * r, where r is odd'''

    t = 0
    r = int(n)
    while r % 2 == 0 and r > 1:
        r //= 2
        t += 1

    return (t, r)


##-Probabilistic prime test
def isSurelyPrime(n):
    '''Check if n is probably prime. Uses Miller Rabin test.'''

    if n == 2:
        return True

    elif n % 2 == 0:
        return False

    return miller_rabin(n, 15)


def miller_rabin_witness(a, d, s, n):
    '''
    Return True if a is a Miller-Rabin witness.

    - a : the base ;
    - d : odd integer verifying n - 1 = 2^s d ;
    - s : positive integer verifying n - 1 = 2^s d ;
    - n : the odd integer to test primality.
    '''

    r = pow(a, d, n)

    if r == 1 or r == n - 1:
        return False

    for k in range(s):
        r = r**2 % n

        if r == n - 1:
            return False

    return True


def miller_rabin(n, k=15) :
    '''
    Return the primality of n using Miller-Rabin probabilistic primality test.

    - n : odd integer to test the primality ;
    - k : number of tests (Error = 4^(-k)).
    '''

    if n in (0, 1):
        return False

    if n == 2:
        return True

    s, d = max_parity(n - 1)

    for i in range(k) :
        a = randint(2, n - 1)

        if miller_rabin_witness(a, d, s, n):
            return False

    return True


##-iroot
def iroot(n, k):
    '''
    Newton's method to find the integer k-th root of n.

    Return floor(n^(1/k))
    '''

    u, s = n, n + 1

    while u < s:
        s = u
        t = (k - 1) * s + n // pow(s, k - 1)
        u = t // k

    return s



##-Fermat factorisation
def fermat_factor(n):
    '''
    Try to factor n using Fermat's factorisation.
    For n = pq, works better if |q - p| is small, i.e if p and q
    are near sqrt(n).
    '''

    a = iroot(n, 2)

    while not is_square(pow(a, 2) - n):
        a += 1

        if pow(a, 2) - n <= 0:
            return False

    b = isqrt(pow(a, 2) - n)
    return (a - b, a + b)


##-Continued fractions
class ContinuedFraction:
    '''Class representing a continued fraction.'''

    def __init__(self, f):
        '''
        Initialize the class

        - f : the int array representing the continued fraction.
        '''

        if type(f) in (set, list):
            self.f = list(f)

        else:
            raise ValueError('ContinuedFraction: error: `f` should be a list')

        if len(f) == 0:
            raise ValueError('ContinuedFraction: error: `f` should not be empty')

        for j, k in enumerate(f):
            if type(k) != int:
                raise ValueError(f'ContinuedFraction: error: `f` should be a list of int, but `{k}` found at position {j}')


    def __repr__(self):
        '''Return a pretty string representing the fraction.'''

        ret = f'{self.f[-1]}'

        for k in reversed(self.f[:-1]):
            ret = f'{k} + 1/(' + ret + ')'

        return ret


    def __eq__(self, other):
        '''Test the equality between self and the other.'''

        return self.f == other.f


    def eval_rec(self):
        '''Return the evaluation of self.f via a recursive function.'''

        return self._eval_rec(self.f)


    def _eval_rec(self, f_):
        '''The recursive function.'''

        if len(f_) == 1:
            return f_[0]

        return f_[0] + 1/(self._eval_rec(f_[1:]))


    def truncate(self, pos):
        '''
        Return a ContinuedFraction truncated at position `pos` from self.f.

        - pos : the position of the truncation. The element at position `pos` is kept in the result.
        '''

        return ContinuedFraction(self.f[:pos + 1])


    def get_convergents(self):
        '''
        Return two lists, p, q which represents the convergents :
        the n-th convergent is `p[n] / q[n]`.
        '''

        p = [0]*(len(self.f) + 2)
        q = [0]*(len(self.f) + 2)

        p[-1] = 1
        q[-2] = 1

        for k in range(0, len(self.f)):
            p[k] = self.f[k] * p[k - 1] + p[k - 2]
            q[k] = self.f[k] * q[k - 1] + q[k - 2]

        return p, q


    def eval_(self):
        '''Return the evaluation of self.f.'''

        p, q = self.get_convergents()

        return p[len(self.f) - 1] / q[len(self.f) - 1]


    def get_nth_convergent(self, n):
        '''Return the convergent at the index n.'''

        if n >= len(self.f):
            raise ValueError(f'ContinuedFraction: get_nth_convergent: n cannot be greater than {len(self.f) - 1}')

        p, q = self.get_convergents()

        return p[n] / q[n]



def get_continued_fraction(a, b):
    '''Return a ContinuedFraction object, the continued fraction of a/b.'''

    f = []
    d = Fraction(a, b)
    f.append(floor(d))

    while d - floor(d) != 0:
        d = 1/(d - floor(d))
        f.append(floor(d))

    return ContinuedFraction(f)


def get_continued_fraction_real(x):
    '''
    Return a ContinuedFraction object, the continued fraction of x.
    Note that there can be errors because of the float precision with this function.
    '''

    f = []

    d = x
    f.append(floor(x))

    while d - floor(d) != 0:
        d = 1/(d - floor(d))
        f.append(floor(d))

    return ContinuedFraction(f)


def get_continued_fraction_rec(a, b, f=[]):
    '''Return a ContinuedFraction object, the continued fraction of a/b. This is a recursive function.'''

    # euclidean division : a = bq + r
    q = a // b
    r = a % b

    if r == 0:
        return ContinuedFraction(f + [q])

    return get_continued_fraction_rec(b, r, f + [q])


##-Tests
if __name__ == '__main__':
    if False:
        n = int(input('number :\n>'))
        p, q = fermat_factor(n)
        print('Result : {}\np = {}'.format(p*q == n, p))


