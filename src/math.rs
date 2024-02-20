use num_bigint::{BigInt, ToBigInt, RandBigInt};
use num_traits::{cast::FromPrimitive, ToPrimitive};
use ramp::{traits::Integer};


pub fn big_is_prime(n: &BigInt) -> bool //semi probabalistic miller-rabin primality test
{
    if n.is_even() {return false}; //this throws away 2 but it doesn't matter because it is for big integers

    let low_primes = vec![2, 3, 5, 7, 11, 13, 17, 19];
    for &prime in &low_primes
    {
        if n == &BigInt::from_u32(prime).unwrap()
        {
            return true;
        }
        if n.clone() % prime == BigInt::from_u32(0).unwrap()
        {
            return false;
        }
    }

    let mut d = n.clone() - BigInt::from_u32(1).unwrap();
    let mut s = 0;
    while d.is_even()
    {
        d /= 2;
        s += 1;
    }

    let bases = vec![
        BigInt::from(2),
        BigInt::from(325),
        BigInt::from(9375),
        BigInt::from(28178),
        BigInt::from(450775),
        BigInt::from(9780504),
        BigInt::from(1795265022),
    ];

    for base in bases
    {
        let mut x = modexp_fast_internal_copy(base, d.clone(), n.clone());
        if x == BigInt::from_u32(1).unwrap() || x == n - BigInt::from_u32(1).unwrap()
        {
            continue;
        }
        let mut i = 0;
        while i < s - 1 && x != n - BigInt::from_u32(1).unwrap()
        {
            x = modexp_fast_internal_copy(x, BigInt::from_u32(2).unwrap(), n.clone());
            i += 1;
        }
        if x != n - BigInt::from_u32(1).unwrap()
        {
            return false;
        }
    }
    return true
}

pub fn modexp_fast_internal_copy(mut b: BigInt, mut e: BigInt, m: BigInt) -> BigInt
{
    let mut result = BigInt::from_u64(1).unwrap();
    let big1 = BigInt::from_u64(1).unwrap();
    let big2 = BigInt::from_u64(2).unwrap();
    while e > BigInt::from_u64(0).unwrap()
    {
        if e.clone() % big2.clone() == big1
        {
            result = (result.clone() * b.clone()) % m.clone();
        }
        b = (b.clone() * b.clone()) % m.clone();
        e = e.clone() / 2.clone();
    }
    result % m
}

