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
🧝 Bilbo is a simple CLI cyber security tool. Scans files to discover hidden information.

Usage: bilbo <COMMAND>

Commands:
  picklock  Attempts to pick lock the rsa key.
  explain   Explains used algorithms.
  entropy   Calculates Shannon entropy for file content per line and total entropy of a file.
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

- `piclock` - command allows to try RSA private key cracking from the RSA private key.
- `--file` - subcommand allows to provide the file path as an argument.
- `--strong` - subcommand allows to provide number of iterations for strong RSA key cracking attempt and starts the process. If 0 is provided then default value of 1000 will be used. If `--strong` command isn't provided then bilbo will attempt to crack weak RSA key. 