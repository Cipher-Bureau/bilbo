# Bilbo

A small, handcrafted tool for security researchers.

## Lock picking

 - RSA lock pick tries to brute force the week RSA key, use public PEM or exponent and modulus.
 - It shall brake the key in few microseconds if p and q are picked not enough far apart.
 - It attempts to brake the key in 1000 iterations, end if key isn't broken at this point it fails with error.
 - It is possible to increase iterations, but it is very unlikely to brake correctly generated RSA key.

 ## Entropy

 - Shannon entropy is calculated for a slice of bytes that are written in to the `struct` collecting the measurement.
 - Shannon entropy is a measurement of uncertainty or how much information is encoded in the message.

 ## Ping Smuggler

 - Smuggles the file via ping protocol to given ip address in plain text.
 - Smuggles the file via ping protocol to given ip address encrypted by 16 bytes AES key. 

 ## Development 

1. Make sure test are passing and write tests for new functionalities.

To run test:

```sh
cargo run test --profile test
```

2. Make sure your change or update isn't making performance worst.

To run benchmarks:

```sh
cargo bench
```

## Build

Build the bilbo executable for your architecture:

```sh
cargo build --release
```

or for another architecture:

```sh
cargo build --release --target <cpu-required_architecture>
```

 ## Usage

 **This is a fun project, treat it lightly.**

```sh
🧝 Bilbo is a simple CLI cyber security tool. Scans files to discover hidden information and helps send them secretly.

Usage: bilbo <COMMAND>

Commands:
  smuggle   Smuggles the file via ping.
  picklock  Attempts to pick lock the rsa key.
  explain   Explains used algorithms.
  entropy   Calculates Shannon entropy for file content per line and total entropy of a file.
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help

PICKLOCK:
Attempts to pick lock the rsa key.

Usage: bilbo picklock [OPTIONS]

Options:
      --file <FILE>     Path to file in PEM format to be lock picked
      --strong <ITERS>  Number of primes to iterate over. Primes are randomly generated
      --report <LEVEL>  Level of reporting. 0 (default): Only results. 1: Important steps only. 2: Information about number of primes checked.
  -h, --help            Print help
  -V, --version         Print version

ENTROPY:
Calculates Shannon entropy for file content per line and total entropy of a file.

Usage: bilbo entropy [OPTIONS]

Options:
      --file <FILE>     Path to file.
      --report <LEVEL>  Level of reporting. 0 (default): Only results. 1: Important steps only. 2: All foundings such as each line entropy.
  -h, --help            Print help
  -V, --version         Print version

SMUGGLE:
Smuggles the file via ping.

Usage: bilbo smuggle [OPTIONS]

Options:
      --file <FILE>    Path to file in PEM format to be smuggled
      --ip <IP>        IPv4 to the server that will collect smuggled file.
      --encrypt <KEY>  Encryption key.
  -h, --help           Print help
  -V, --version        Print version

```