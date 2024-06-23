/// RSA PickLock algorithm is cracking RSA private key when p and q are not to far apart.
/// Crack Weak Private is able to crack secured RSA keys, where p and q are picked to be close numbers,
/// Based on https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
/// With common RSA key sizes (2048 bit) in tests,
/// the Fermat algorithm with 100 rounds reliably factors numbers where p and q differ up to 2^517.
/// In other words, it can be said that primes that only differ within the lower 64 bytes
/// (or around half their size) will be vulnerable.
/// If this tool cracks your key, you are using insecure RSA algorithm.
/// e - public exponent
/// n - modulus
/// d - private exponent
/// e and n are bytes representation of an integer in big endian order.
/// Returns private key as bytes representation of an integer in big endian order or error otherwise.
/// Will not go further then 1000 iterations.

use openssl::{bn::{BigNum, BigNumRef}, error, rsa::Rsa};
use std::{collections::HashSet, io::{Error, ErrorKind, Result}};
use num_bigint::{BigInt, BigUint, Sign};
use pem::{Pem, encode};
use std::fmt::{Display, Formatter, Result as FmtResult};
use num_prime::nt_funcs::is_prime;

const MAX_ITERATIONS: usize = 1000;
const BITS_IN_BYTE: u32 = 8;

/// Describes the Key type. 
pub enum KeyType {
    Private,
    Public,
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", match &self {
            KeyType::Private => "PRIVATE KEY",
            KeyType::Public => "PUBLIC KEY",
        })
    }
}


#[inline(always)]
fn generate_safe_prime_bit_size(bits: u32) -> Result<BigNum> {
    if bits == 0 {
        return Err(Error::new(ErrorKind::InvalidInput, format!("size cannot be less then 1 received {bits}")));
    }
    let mut bn = BigNum::new()?;
    BigNumRef::generate_prime(&mut bn, bits as i32, true, None, None)?;
    Ok(bn)
}

/// A PickLock for a RSA key and run brute force cracking.
/// 
pub struct PickLock {
    e: BigInt,
    n: BigInt,
    max_iter: usize,
}

impl PickLock {
    /// Creates a new PickLock as and imprint of public RSA key to perform RSA key cracking.
    ///
    #[inline(always)]
    pub fn from_pem(rsa_pem: &str) -> Result<Self> {
        let public_rsa = Rsa::public_key_from_pem(rsa_pem.as_bytes())
            .or_else(|e: error::ErrorStack| Err(Error::new(ErrorKind::InvalidData, e.to_string())))?;
            
        Ok(Self{
            e: BigInt::from_bytes_be(Sign::Plus, &public_rsa.e().to_vec()),
            n: BigInt::from_bytes_be(Sign::Plus, &public_rsa.n().to_vec()),
            max_iter: MAX_ITERATIONS,
        })
    }

    /// Straight forward way to creates a new PickLock from publicly known exponent and modulus.
    /// 
    #[inline(always)]
    pub fn from_exponent_and_modulus(e: BigInt, n: BigInt) -> Self {
        Self{e, n, max_iter: MAX_ITERATIONS}
    }

    /// Alters max iteration that is a safety cap on how many iterations can be performed for a brute force calculation.
    /// It is very likely that badly picked p and q primes can be rediscovered - calculated within 100 iterations.
    /// Default number of iterations is set to 1000, which is way above expected possibility to crack the key.
    ///   
    #[inline(always)]
    pub fn alter_max_iter(&mut self, iter: usize) {
        self.max_iter = iter;
    } 

    /// Attempts to lock pick the weak private RSA key, 
    /// by iteratively finding close apart p and q primes used 
    /// to generate Private Keys based on Public Key.
    /// If it succeeds then the numeric value is returned, 
    /// and this value may be used to create PEM certificate.
    /// 
    #[inline(always)]
    pub fn try_lock_pick_weak_private(&self) -> Result<BigInt> {
        let mut a = self.n.sqrt() + BigInt::new(Sign::Plus, vec![1]);
        let mut b = BigInt::new(Sign::Plus, vec![0]);

        for _ in 0..self.max_iter {
            let a_sqr = &a * &a;
            let b_rest = &a_sqr - &self.n;
            let b_rest_sqrt = b_rest.sqrt();
            if &b_rest_sqrt * &b_rest_sqrt == b_rest {
                b = b_rest_sqrt;
                break;
            }
            a = &a + BigInt::new(Sign::Plus, vec![1]);
        }

        let p = &a + &b;
        let q = &a - &b;

        if &p * &q != self.n {
            return Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("cannot crack the private exponent of the given n {} and e {}", 
                        self.n, 
                        self.e
                    )
                )
            );
        }

        let phi = (&p - BigInt::new(Sign::Plus, vec![1])) * (&q - BigInt::new(Sign::Plus, vec![1]));
        

        match self.e.modinv(&phi) {
            Some(r) => Ok(r),
            None => Err(Error::new(
                ErrorKind::Other, 
                format!("cannot calculate private exponent for phi {} and e {}", phi, self.e))
            ),
        }
    }

    /// Attempts to lock pick the strong private RSA key, 
    /// by making number of guesses about far apart p and q primes used 
    /// to generate Private Keys based on Public Key.
    /// If it succeeds then the numeric value is returned, 
    /// and this value may be used to create PEM certificate.
    ///
    /// NOTE: It is a PROTOTYPE ONLY. 
    /// It is not guaranteed to work at all.
    /// There is just to many primes to check, so even thou 
    /// it generates a lot of primes, it is still a matter of luck
    /// to find the matching pair.
    /// 
    /// TODO: Make more research and tests to find out how much information can we get to better guess primes.
    /// 
    #[inline(always)]
    pub fn try_lock_pick_strong_private(&self, report: bool) -> Result<BigInt> {
        let p_size = self.n.to_bytes_be().1.len() as u32 / 2;
        let mut p = BigInt::new(Sign::Plus, vec![0]);
        let mut q = BigInt::new(Sign::Plus, vec![0]);
        let mut sum_of_checked_primes = 0;
        let mut passed_first = false;

        for diff in 0..=2 { // Since n = p*q, the size of n will be more or less the sum of the sizes of p and q with +/- 1 bit
            let mut checked_primes: HashSet<BigInt> = HashSet::with_capacity(self.max_iter);
            let diff: i32 = diff as i32 - 1;
            'next_prime_lookup: for n in 0..self.max_iter {
                if report && n % 25 == 0 && passed_first {
                    println!("Checked {} primes.", sum_of_checked_primes + checked_primes.len());
                }
                passed_first = true;

                p = BigInt::from_bytes_be(
                    Sign::Plus, 
                    &generate_safe_prime_bit_size(((p_size * BITS_IN_BYTE) as i32 - diff) as u32)?.to_vec(),
                );
                if !checked_primes.insert(p.clone()) {
                    continue 'next_prime_lookup;
                }

                q = &self.n / &p;
 
                if &p * &q != self.n {
                    continue 'next_prime_lookup;
                }
                let Some(q_uint) = q.to_biguint() else {
                    return Err(Error::new(ErrorKind::InvalidData, "cannot transform BigInt to BigUint"));
                };
                if is_prime::<BigUint>(&q_uint, None).probably() {
                    break;
                }
            }
            sum_of_checked_primes += checked_primes.len();
        }
        
        if report {
            println!("Checked {} primes.", sum_of_checked_primes);
        }
        
        if &p * &q != self.n { // Final test in case 'next_prime_lookup loop is exhausted without finding p and q.
            return Err(
                Error::new(
                    ErrorKind::Other, 
                    format!("cannot crack the private exponent of the given n {} and e {}", 
                        self.n, 
                        self.e
                    )
                )
            );
        }

        let phi = (&p - BigInt::new(Sign::Plus, vec![1])) * (&q - BigInt::new(Sign::Plus, vec![1]));
        

        match self.e.modinv(&phi) {
            Some(r) => Ok(r),
            None => Err(Error::new(
                ErrorKind::Other, 
                format!("cannot calculate private exponent for phi {} and e {}", phi, self.e))
            ),
        }
    }
} 

impl Display for PickLock {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "e: {} [ bytes {} ], n: {} [ bytes {} ], iter: {},", self.e, self.e.to_bytes_be().1.len(), self.n, self.n.to_bytes_be().1.len(), self.max_iter)
    }
}

/// Attempts to convert BigInt into a String in Pem format.
/// 
#[inline(always)]
pub fn to_pem(d: BigInt, kt: KeyType) -> Result<String> {
    Ok(encode(&Pem::new(kt, d.to_bytes_be().1)))
}


#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::BigNum;

    #[test]
    fn it_should_generate_prime_number_and_validate_it_with_success() {
        for bytes in (8..=64).step_by(8) {
            let Ok(p1) = generate_safe_prime_bit_size(bytes * BITS_IN_BYTE) else {
                assert!(false);
                return;
            };
            let p1 = BigInt::from_bytes_be(Sign::Plus, &p1.to_vec());
            let Some(p1) = p1.to_biguint() else {
                assert!(false);
                return;
            };
            assert!(is_prime::<BigUint>(&p1, None).probably());
        }
    }

    #[test]
    fn it_should_not_crack_with_pick_lock_weak_private_the_secure_rsa() {
        const PUBLIC_KEY_SAMPLE: &'static str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp2Z+WFY2ygdgPMnWpJNxqtuweA1nix
kTirAEQ+F3NKfNEdR9J/+Rq+2ViT3wnamtuBG+10SKuKjr9FKhh/T0sCAwEAAQ==
-----END PUBLIC KEY-----
";

        let Ok(pl) = PickLock::from_pem(&PUBLIC_KEY_SAMPLE) else {
            assert!(false);
            return;
        };
        println!("PickLock: {pl}");

        let Err(_e) = pl.try_lock_pick_weak_private() else {
            assert!(false);
            return;
        };

        assert!(true);

    }

    #[test]
    pub fn it_should_crack_with_pick_lock_weak_private_the_unsecure_rsa() {
        struct TestCase {
            n: BigInt,
            e: BigInt,
            d: BigInt,
        }
        let Ok(large_n) = BigNum::from_dec_str("24051723933323373230335109652699872887260372863633030520380856590934224554506308944154529656903683098544282868895265857723676740447085769973038138116162852753658181861191950778361549639563565516085451073539560657386103501608592321148669427604194877552133864887585897064910317370632491325912646759075452895764136071794899761625652745642888012193592843601786282707419064157922868466879644136792854722277212465067471658496818060980989808791352963906077940588038623347540668963885547785982543883250789113853569537794783330309654648546163063571756203834919697878945651911998161025323667873893944714006021586935213636888431") else {
            assert!(false);
            return;
        };
        let Ok(large_d) = BigNum::from_dec_str("20859605057389981400415296665239606253551311979432043299936333792698939369418558891569637169366135826146428643134992692481438916188899523620207130817470747633629513081286743218201811495234043370443885950972963184234382668232155560092302387896834347699555010854105235260577040893379009940545782216749159515118484219566373157731404293321389017417036945992984437162056145246504943473128453889715274064071687926343900718250671226003207988553491071490774949729393790264296526140962891140650428560103645538027632465103573248308915991466476312603275778085679414182339076676621372222055380237829179961993191380693342799887257") else {
            assert!(false);
            return;
        };

        let test_cases: Vec<TestCase> = vec![
            TestCase{
                n: BigInt::new(Sign::Plus, vec![63648259]), 
                e: BigInt::new(Sign::Plus, vec![65537]), 
                d: BigInt::new(Sign::Plus, vec![27903761])
            },
            TestCase{
                n: BigInt::from_bytes_be(Sign::Plus, &large_n.to_vec()), 
                e: BigInt::new(Sign::Plus, vec![65537]), 
                d: BigInt::from_bytes_be(Sign::Plus, &large_d.to_vec()), 
            },
        ];

        for tc in test_cases.iter() {
            let pl = PickLock::from_exponent_and_modulus(tc.e.clone(), tc.n.clone());
            let Ok(res) = pl.try_lock_pick_weak_private() else {
                assert!(false);
                return;
            };
            assert_eq!(res, tc.d);
            println!("\n{:?}", to_pem(res, KeyType::Private).unwrap_or_default());
        }
    }
    
    #[test]
    fn it_should_try_to_crack_with_pick_lock_strong_private_the_secure_rsa() {
        const PUBLIC_KEY_SAMPLE: &'static str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp2Z+WFY2ygdgPMnWpJNxqtuweA1nix
kTirAEQ+F3NKfNEdR9J/+Rq+2ViT3wnamtuBG+10SKuKjr9FKhh/T0sCAwEAAQ==
-----END PUBLIC KEY-----
";

        let Ok(mut pl) = PickLock::from_pem(&PUBLIC_KEY_SAMPLE) else {
            assert!(false);
            return;
        };
        pl.alter_max_iter(1_000);

        match pl.try_lock_pick_strong_private(true) {
            Ok(key) => println!("SUCCESS:\n{key}"),
            Err(e) => println!("FAILURE:\n{e}"),
        }


    }
}