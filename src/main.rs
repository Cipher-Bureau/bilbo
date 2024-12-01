use bilbo::entropy;
use bilbo::errors::BilboError;
use bilbo::rsa::{to_pem, KeyType, PickLock};
use bilbo::smuggler::{ping_cipher, ping_plain, Config};
use clap::{arg, command, value_parser, Command};
use shamirss::{
    combine_inlined, create_inlined, decode_secret_to_bytes, decode_shares_to_bytes,
    encode_secret_bytes, encode_shares_bytes, EncodingStd,
};
use std::fs::read_to_string;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

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
 -> p and q are primes that differs in more than first 2^517 - last 64 bytes.
 -> p and q are fairly equal in bits size and can vary +/- 1 bit,
 -> bits size of p + bits size of q are equal to n,

[ 🧮 ] Bilbo offers entropy calculation.

The Shannon entropy is a statistical quantifier extensively used for the characterization of complex processes. It is capable of detecting nonlinearity aspects in model series, contributing to a more reliable explanation regarding the nonlinear dynamics of different points of analysis, which in turn enhances the comprehension of the nature of complex systems characterized by complexity and nonequilibrium.
In addition to complexity and nonequilibrium, most, not all, complex systems also have the characteristic of being marked by heterogeneous distributions of links.
The concept of entropy was used by Shannon in information theory for the data communication of computer sciences and is known as Shannon entropy.
Based on this concept, the mean value of the shortest possibilities required to code a message is the division of the symbol logarithm in the alphabet by the entropy.
Entropy refers to a measurement of vagueness and randomness in a system. If we assume that all the available data belong to one class, it will not be hard to predict the class of a new data.

[ 📦 ] Message smuggler via ping.

The message smuggler via ping allows to smuggle message in plain text or encrypted message with 16 bytes long key via ping.
Smuggler may be useful when proxy blocks internet traffic but allows ping and you want to send message outside.
Encryption used for the message is EAS and encrypts 16 bytes long blocks that are collected in to buffer and then
sent via ping in 24 bytes long chunks. The initialization vector is transferred on the end of communication in plaintext.

[ 🧩 ] Shamirs Secret Sharing algorithm.

The Shamirs Secret Sharing is an efficient secret sharing algorithm for distributing private information (the secret) among a group. The secret cannot be revealed unless a quorum of the group acts together to pool their knowledge. To achieve this, the secret is mathematically divided into parts (the shares) from which the secret can be reassembled only when a sufficient number of shares are combined. SSS has the property of information-theoretic security, meaning that even if an attacker steals some shares, it is impossible for the attacker to reconstruct the secret unless they have stolen the quorum number of shares.
";

const MINIMUM_SHARES: usize = 10;
const TOTAL_SHARES: usize = 20;

fn main() {
    let cmd = Command::new("bilbo")
        .bin_name("bilbo")
        .subcommand_required(true)
        .about("🧝 Bilbo is a simple CLI cyber security tool. Scans files to discover hidden information and helps send them secretly.")
        .subcommand(
            command!("smuggle")
            .about("Smuggles the file via ping.")
            .arg(
                arg!(--"file" <FILE> "Path to file in PEM format to be smuggled")
                    .value_parser(value_parser!(PathBuf)),
            ).arg(
                arg!(--"ip" <IP> "IPv4 to the server that will collect smuggled file.").value_parser(value_parser!(Ipv4Addr)),
            ).arg(
                arg!(--"encrypt" <KEY> "Encryption key.").value_parser(value_parser!(Vec<u8>)),
            )
        )
        .subcommand(
            command!("picklock")
            .about("Attempts to pick lock the rsa key.")
            .arg(
                arg!(--"file" <FILE> "Path to file in PEM format to be lock picked")
                    .value_parser(value_parser!(PathBuf)),
            ).arg(
                arg!(--"strong" <ITERS> "Number of primes to iterate over. Primes are randomly generated").value_parser(value_parser!(u32)),
            ).arg(
                arg!(--"report" <LEVEL> "Level of reporting. 0 (default): Only results. 1: Important steps only. 2: Information about number of primes checked.").value_parser(value_parser!(u8)),
            ),
        ).subcommand(
            command!("explain").about("Explains used algorithms."),
        ).subcommand(
            command!("shamirs")
            .about("Shamirs create shares from secret or collects shares to secret.")
            .arg(
                arg!(--"file" <FILE> "Path to file with secret or shares.").value_parser(value_parser!(PathBuf))
            )
            .arg(arg!(--"secret" "Tries to reconstruct secrets from file with secret shares."))
            .arg(arg!(--"shares" "Tries to crate a shares from file with secret."))
            .arg(arg!(--"minimum" <usize> "Minimum number of shares to reconstruct given secret, it shall be less or equal to total. Default 10").value_parser(value_parser!(usize)))
            .arg(arg!(--"total" <usize> "Total number of shares to crate for given secret. Default 20").value_parser(value_parser!(usize)))
            .arg(arg!(--"encoding" <String> "File encoding 'hex' or 'base64'. Default 'base64'").value_parser(value_parser!(String)))
        ).subcommand(
            command!("entropy")
            .about("Calculates Shannon entropy for file content per line and total entropy of a file.")
            .arg(
                arg!(--"file" <FILE> "Path to file.")
                    .value_parser(value_parser!(PathBuf)),
            ).arg(
                arg!(--"report" <LEVEL> "Level of reporting. 0 (default): Only results. 1: Important steps only. 2: All foundings such as each line entropy.").value_parser(value_parser!(u8)),
            )
        );
    let matches = cmd.get_matches();
    match matches.subcommand() {
        Some(("picklock", matches)) => {
            match run_picklock(
                matches.get_one::<PathBuf>("file"),
                matches.get_one::<u32>("strong"),
                matches.get_one::<u8>("report"),
            ) {
                Ok(s) => println!("🗝 Lock picked private PEM key:\n{s}\n"),
                Err(e) => println!("🤷 LockPick Failure: {}", e),
            }
        }
        Some(("entropy", matches)) => {
            match run_entropy(
                matches.get_one::<PathBuf>("file"),
                matches.get_one::<u8>("report"),
            ) {
                Ok(s) => println!("📶 Entropy:\n{s}\n"),
                Err(e) => println!("🤷 Entropy Failure: {}", e),
            }
        }
        Some(("smuggle", matches)) => match smuggle_file_via_ping(
            matches.get_one("file"),
            matches.get_one("ip"),
            matches.get_one("encrypt"),
        ) {
            Ok(s) => println!("📦 Ping Smuggler: \n{s}\n"),
            Err(e) => println!("🤷 Failure: {}", e),
        },
        Some(("shamirs", matches)) => {
            match run_shamirs(
                matches.get_one::<PathBuf>("file"),
                matches.get_one::<bool>("secret"),
                matches.get_one::<bool>("shares"),
                matches.get_one::<usize>("minimum"),
                matches.get_one::<usize>("total"),
                matches.get_one::<String>("encoding"),
            ) {
                Ok(s) => println!("{s}"),
                Err(e) => println!("🤷 Shamirs Secret Sharing Failure: {}", e),
            }
        }
        Some(("explain", _matches)) => println!("{EXPLAIN}"),
        None => (),
        _ => unreachable!("unreachable code"),
    };
}

#[inline(always)]
fn run_shamirs(
    path: Option<&PathBuf>,
    secret: Option<&bool>,
    shares: Option<&bool>,
    minimum: Option<&usize>,
    total: Option<&usize>,
    encoding: Option<&String>,
) -> Result<String, BilboError> {
    let Some(path) = path else {
        return Err(BilboError::GenericError(
            "I received an empty file path... I don't know what file to use for Shamir Secret Sharing, please be specific..."
                .to_string(),
        ));
    };
    let Some(secret) = secret else {
        return Err(BilboError::GenericError(
            "Please specify option secret.".to_string(),
        ));
    };
    let Some(shares) = shares else {
        return Err(BilboError::GenericError(
            "Please specify option secret.".to_string(),
        ));
    };

    if *secret && *shares {
        return Err(BilboError::GenericError(
            "Only one option --secret or --shares is allowed. Pick only one please.".to_string(),
        ));
    }
    if !*secret && !*shares {
        return Err(BilboError::GenericError(
            "At least one option --secret or --shares shall be provided. Pick only one please."
                .to_string(),
        ));
    }

    let min = minimum.unwrap_or(&MINIMUM_SHARES);
    let total = total.unwrap_or(&TOTAL_SHARES);
    let encoding = match encoding.unwrap_or(&"base64".to_string()).as_str() {
        "base64" => Ok(EncodingStd::Base64),
        "hex" => Ok(EncodingStd::Hex),
        _ => Err(BilboError::GenericError(
            "Unknown encoding type.".to_string(),
        )),
    }?;

    let file_data = read_to_string(path)?;

    let result = if *secret {
        let lines = file_data
            .lines()
            .map(|a| a.to_string())
            .collect::<Vec<String>>();
        let mut lines_cleaned = Vec::with_capacity(lines.len());
        for line in lines.iter() {
            if line.is_empty() {
                continue;
            }
            lines_cleaned.push(line.to_string());
        }
        let shares = decode_shares_to_bytes(&lines_cleaned, encoding.clone())?;
        let secret = combine_inlined(shares)?;
        encode_secret_bytes(&secret, encoding.clone())
    } else {
        let file_data = file_data.replace('\n', "");
        let secret = decode_secret_to_bytes(&file_data, encoding.clone())?;
        let shares = create_inlined(*min, *total, &secret)?;
        encode_shares_bytes(shares, encoding).join("\n")
    };

    Ok(result)
}

#[inline(always)]
fn run_picklock(
    path: Option<&PathBuf>,
    strong_iters: Option<&u32>,
    report_level: Option<&u8>,
) -> Result<String, BilboError> {
    let report_level = check_level(report_level)?;
    let Some(path) = path else {
        return Err(BilboError::GenericError(
            "I received an empty file path... I don't know what to picklock, please be specific..."
                .to_string(),
        ));
    };

    let rsa_pem = read_to_string(path)?;
    let mut pl = PickLock::from_pem(&rsa_pem)?;

    let d = match strong_iters {
        None => {
            if report_level >= 1 {
                println!("🔐 Starting lock picking the weak RSA private key.\n");
            }
            pl.try_lock_pick_weak_private()?
        }
        Some(iter) => {
            if report_level >= 1 {
                println!("🔐 Starting lock picking the strong RSA private key.\n");
            }
            if *iter != 0 {
                pl.alter_max_iter(*iter as usize)?;
            }
            pl.try_lock_pick_strong_private(report_level == 2)?
        }
    };
    let pem_priv = to_pem(d, KeyType::Private)?;

    Ok(pem_priv)
}

#[inline(always)]
fn run_entropy(path: Option<&PathBuf>, report_level: Option<&u8>) -> Result<String, BilboError> {
    let report_level = check_level(report_level)?;
    if report_level >= 1 {
        println!("🧮 Starting Shannon entropy calculation.\n");
    }
    let Some(path) = path else {
        return Err(BilboError::GenericError(
            "I received an empty file path... I don't know what file to calculate entropy for, please be specific...".to_string()
        ));
    };

    let data = read_to_string(path)?;

    let mut result = String::new();
    let mut total_entropy = entropy::Shannon::new();
    let mut total_bts: usize = 0;

    result.push_str(&format!(
        "| {0: <6} | {1: <8} | {2: <7} | {3: <5} | {4: <24} |\n",
        "Line", "Entropy", "Bytes", "Ratio", "Starts with"
    ));
    result.push_str("|================================================================|\n");

    for (i, line) in data.lines().enumerate() {
        let mut ent = entropy::Shannon::new();
        let buf = line.as_bytes();

        total_entropy.write_all(buf)?;
        total_entropy.process();
        let bts = buf.len();
        total_bts += bts;
        if report_level == 2 {
            ent.write_all(buf)?;
            ent.process();
            let e = ent.get_entropy();
            let ratio = if bts == 0 { 0 } else { e / bts as u64 };
            result.push_str(&format!(
                "| {0: <6} | {1: <8} | {2: <7} | {3: <5} | {4: <21}... |\n",
                i + 1,
                e,
                bts,
                ratio,
                &line[..if line.len() < 21 { line.len() } else { 21 }]
            ));
        }
    }

    let total_entropy = total_entropy.get_entropy();
    let ratio = if total_bts == 0 {
        0
    } else {
        total_entropy / total_bts as u64
    };

    if report_level == 2 {
        result.push_str("|================================================================|\n");
    }
    result.push_str(&format!(
        "| {0: <6} | {1: <8} | {2: <7} | {3: <5} | {4: <24} |\n",
        "TOTAL", total_entropy, total_bts, ratio, "         ---"
    ));

    Ok(result)
}

#[inline(always)]
fn smuggle_file_via_ping(
    file: Option<&PathBuf>,
    ip: Option<&Ipv4Addr>,
    key: Option<&Vec<u8>>,
) -> Result<String, BilboError> {
    let Some(path) = file else {
        return Err(BilboError::GenericError(
            "empty or incorrect file path".to_string(),
        ));
    };
    let Some(ip) = ip else {
        return Err(BilboError::GenericError(
            "empty or incorrect ip address".to_string(),
        ));
    };

    let data = read_to_string(path)?;

    match key {
        None => {
            ping_plain(IpAddr::V4(*ip), data.as_bytes(), &Config::default())?;
            Ok(format!("File {:?} smuggled to {}\n", path.as_os_str(), ip).to_string())
        }
        Some(k) => {
            if k.len() != 16 {
                return Err(BilboError::GenericError(format!(
                    "incorrect kye size, expected 16 bytes, got {} bytes",
                    k.len()
                )));
            }

            let cfg = Config::default();
            let mut enc_key: [u8; 16] = [0; 16];
            enc_key.copy_from_slice(&k[..16]);

            let ip = IpAddr::V4(*ip);
            let vi = ping_cipher(ip, data.as_bytes(), &enc_key, &cfg)?;
            ping_plain(ip, &vi, &cfg)?;

            Ok(format!(
                "File {:?} smuggled to {}, with IV: {:?} \n",
                path.as_os_str(),
                ip,
                vi
            )
            .to_string())
        }
    }
}

#[inline(always)]
fn check_level(level: Option<&u8>) -> Result<u8, BilboError> {
    let level = *level.unwrap_or(&0);
    match level {
        0..=2 => Ok(level),
        _ => Err(BilboError::GenericError(format!(
            "Expected level 0, 1 or 2, got {level}"
        ))),
    }
}
