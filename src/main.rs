use bilbo::entropy;
use clap::{Command, command, arg, value_parser};
use std::path::PathBuf;
use std::io::{Error, ErrorKind, Result, Write};
use std::fs::read_to_string;
use bilbo::rsa::{PickLock, to_pem, KeyType};

const EXPLAIN: &str = "
[ 🐉 🏔 💎 ] BILBO

[ 🔐 ] Bilbo offers two RSA cracking algorithms.

1. Weak 😜: 
Is cracking RSA private key when p and q are not to far apart.
Crack Weak Private is able to crack secured RSA keys, where p and q are picked to be close numbers,
Based on https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
With common RSA key sizes (2048 bit) in tests,
the Fermat algorithm with 100 rounds reliably factors numbers where p and q differ up to 2^517.
In other words, it can be said that primes that only differ within the lower 64 bytes
(or around half their size) will be vulnerable.
If this tool cracks your key, you are using insecure RSA algorithm.
e - public exponent
n - modulus
d - private exponent
e and n are bytes representation of an integer in big endian order.
Returns private key as bytes representation of an integer in big endian order or error otherwise.
Will not go further then 1000 iterations.

2. Strong 💪:
Is cracking RSA when p and q are far apart.
Similar in terms of factorization to weak algorithm, but works on the principal that RSA p and q
are chosen according to the specification where:
 -> p * q = n,
 -> p and q are primes that differs more in more than first 2^517 - last 64 bytes.
 -> p and q are fairly equal in bits size and can vary +/- 1 bit,
 -> bits size of p + bits size of q are equal to n,

[ 🧮 ] Bilbo offers entropy calculation.

The Shannon entropy is a statistical quantifier extensively used for the characterization of complex processes. 
It is capable of detecting nonlinearity aspects in model series, 
contributing to a more reliable explanation regarding the nonlinear dynamics of different points of analysis,
which in turn enhances the comprehension of the nature of complex systems characterized by complexity and nonequilibrium.
In addition to complexity and nonequilibrium, most, not all, complex systems also have the characteristic of being marked 
by heterogeneous distributions of links.
The concept of entropy was used by Shannon in information theory for the data communication of computer sciences
and is known as Shannon entropy.
Based on this concept, the mean value of the shortest possibilities required to code a message is the division
of the symbol logarithm in the alphabet by the entropy.
Entropy refers to a measurement of vagueness and randomness in a system
. If we assume that all the available data belong to one class, 
it will not be hard to predict the class of a new data.
";

fn main() {
    let cmd = Command::new("bilbo")
        .bin_name("bilbo")
        .subcommand_required(true)
        .about("🧝 Bilbo is here to help you on your journey to unlock precious items.")
        .subcommand(
            command!("picklock")
            .about("Attempts to pick lock the rsa key.")
            .arg(
                arg!(--"file" <FILE> "Path to file in PEM format to be lock picked")
                    .value_parser(value_parser!(PathBuf)),
            ).arg(
                arg!(--"strong" <ITERS>).value_parser(value_parser!(u32)),
            )
        ).subcommand(
            command!("explain"). about("Explains used algorithms."),
        ).subcommand(
            command!("entropy")
            .about("Calculates Shannon entropy for file content per line and total entropy of a file.")
            .arg(
                arg!(--"file" <FILE> "Path to file.")
                    .value_parser(value_parser!(PathBuf)),
            )
        );
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("picklock", matches)) =>  {
            match run_picklock(matches.get_one::<PathBuf>("file"), 
            matches.get_one::<u32>("strong")) {
                Ok(s) => println!("🗝 Lock picked private PEM key:\n{s}\n"),
                Err(e) => println!("🤷 Failure: {}", e.to_string()),
            }
        },
        Some(("entropy", matches)) => {
            match run_entropy(matches.get_one::<PathBuf>("file")) {
                Ok(s) => println!("📶 Entropy:\n{s}\n"),
                Err(e) => println!("🤷 Failure: {}", e.to_string()),
            }

        },
        Some(("explain", _matcher)) => println!("{EXPLAIN}"),
        None => (),
        _ => unreachable!("unreachable code"),
    };   
}

fn run_picklock(path: Option<&PathBuf>, strong_iters: Option<&u32>) -> Result<String> {
    let Some(path) = path else { 
        return Err(Error::new(
            ErrorKind::InvalidInput, 
            "I received an empty file path... I don't know what to picklock, please be specific..."
        ))
    };

    let rsa_pem = read_to_string(path)?;
    let mut pl = PickLock::from_pem(&rsa_pem)?;

    let d = match strong_iters {
        None => {
            println!("🔐 Starting lock picking the weak RSA private key.\n");
            pl.try_lock_pick_weak_private()?
        },
        Some(iter) => {
            println!("🔐 Starting lock picking the strong RSA private key.\n");
            if *iter != 0 {
                pl.alter_max_iter(*iter as usize);
            }
            pl.try_lock_pick_strong_private(true)?
        }
    };
    let pem_priv = to_pem(d, KeyType::Private)?; 

    Ok(pem_priv)
}

fn run_entropy(path: Option<&PathBuf>) -> Result<String> {
    println!("🧮 Starting Shannon entropy calculation.\n");
    let Some(path) = path else { 
        return Err(Error::new(
            ErrorKind::InvalidInput, 
            "I received an empty file path... I don't know what to picklock, please be specific..."
        ))
    };

    let data = read_to_string(path)?;

    let mut sum = 0;
    let mut result = String::new();

    for (i, line) in data.lines().enumerate() {
        let mut ent = entropy::Shannon::new();
        ent.write(line.as_bytes())?;
        ent.process();
        let e = ent.get_entropy();
        result.push_str(&format!("Line {i} [ {e} ]\n"));
        sum += e;
    }
    result.push_str(&format!("Total [ {sum} ]\n")); 

    Ok(result)
}