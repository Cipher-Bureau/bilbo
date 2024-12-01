use crate::errors::BilboError;
use std::collections::HashMap;
use std::io::Write;
use std::str::from_utf8;

const CHUNK_SIZE: usize = 128;

/// Shannon perform preprocessing of the information in given buffer.
///
/// Shannon calculates the message entropy.
/// In information theory, the entropy of a random variable is the average level of
/// "information", "surprise", or "uncertainty" inherent to the variable's possible outcomes.
/// Given a discrete random variable 𝑋 which takes values in the set 𝑋 and is distributed according to
/// p: X -> [0, 1], the entropy is H(X) := - Sum(p(x)log p()x).
///
#[derive(Debug, Default)]
pub struct Shannon {
    buf: Vec<u8>,
    entropy: u64,
    freq: HashMap<u8, f64>,
}

impl Shannon {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(CHUNK_SIZE),
            entropy: 0,
            freq: HashMap::with_capacity(CHUNK_SIZE),
        }
    }

    #[inline(always)]
    pub fn process(&mut self) {
        self.entropy = self.shannon();
    }

    #[inline(always)]
    pub fn get_entropy(&self) -> u64 {
        self.entropy
    }

    #[inline(always)]
    pub fn get_token_str(&self) -> Result<&str, BilboError> {
        Ok(from_utf8(&self.buf)?)
    }

    #[inline(always)]
    pub fn get_token_bytes(&self) -> &[u8] {
        &self.buf
    }

    #[inline(always)]
    pub fn get_occurrence(&self, byte: &u8) -> u64 {
        *self.freq.get(byte).unwrap_or(&0_f64) as u64
    }

    #[inline(always)]
    fn shannon(&mut self) -> u64 {
        for b in self.buf.iter() {
            self.freq
                .entry(*b)
                .and_modify(|v| *v += 1_f64)
                .or_insert(1_f64);
        }
        let div: f64 = self.buf.len() as f64;
        let sum = self.freq.iter().fold(0_f64, |mut acc, (_, v)| {
            let f = v / div;
            acc += f * f64::log2(f);
            acc
        }) * -1_f64;
        f64::ceil(sum) as u64 * div as u64
    }
}

impl Write for Shannon {
    #[inline(always)]
    fn write_all(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        self.buf.extend_from_slice(buf);
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    #[inline(always)]
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.buf = Vec::with_capacity(CHUNK_SIZE);
        self.entropy = 0;
        self.freq = HashMap::with_capacity(CHUNK_SIZE);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, iter::zip};

    use super::Shannon;

    #[test]
    fn it_should_calculate_shannon_entropy_of_given_information_buffers() {
        let given: [&str; 17] = [
            "123",
            "password",
            "myCa7I5a60d",
            "m#P52s@ap$V",
            "IthinkItIsVeryStrong",
            "7k289be923hv934",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjtGIk8SxD+OEiBpP2/T",
            "JUAF0upwuKGMk6wH8Rwov88VvzJrVm2NCticTk5FUg+UG5r8JArrV4tJPRHQyvqK",
            "wF4NiksuvOjv3HyIf4oaOhZjT8hDne1Bfv+cFqZJ61Gk0MjANh/T5q9vxER/7TdU",
            "NHKpoRV+NVlKN5bEU/NQ5FQjVXicfswxh6Y6fl2PIFqT2CfjD+FkBPU1iT9qyJYH",
            "A38IRvwNtcitFgCeZwdGPoxiPPh1WHY8VxpUVBv/2JsUtrB/rAIbGqZoxAIWvijJ",
            "Pe9o1TY3VlOzk9ASZ1AeatvOir+iDVJ5OpKmLnzc46QgGPUsjIyo6Sje9dxpGtoG",
            "MIHsAgEAMBQGByqGSM49AgEGCSskAwMCCAEBDgSB0DCBzQIBAQRApRcuc7AWM9CA",
            "/rkD6WpxeDC2nucjauXVQgD2DEw3e1UEfiAtq5FmilGKkatZnFV8arTbREZs2+3c",
            "FlOId1p1K6GBhQOBggAEVWiPAqU0fQG8y+uQZPTo62vcw5bmbkuTeHJg4YRdOyYK",
            "9T9MYS/6PpWd8yzRdzLtIhyBfYhcMy814OzZjddsD5v2Npsms+3Ewr+8GY8o88ED",
            "d/xfnUnA1VpdI1n1DCAOow9BFXFxWrSHh3LvRg3h1twLSIbBwvsXr8o1zoQuMuY=",
        ];
        let expected: [u64; 17] = [
            6, 24, 44, 44, 80, 60, 320, 384, 384, 384, 384, 384, 320, 384, 384, 384, 384,
        ];

        for (g, e) in zip(given, expected) {
            let mut pre = Shannon::new();
            let _ = pre.write(g.as_bytes());
            let result = pre.shannon();
            assert_eq!(result, e);
        }
    }

    #[test]
    fn it_should_process_string_and_calculate_occurrence() {
        let given: [&str; 6] = [
            "asdfghjklasdfghjklasdfghjkl",
            "qwertyuiopqwertyuiopqweraqw",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1231234534575695wadasdfasfs",
            "qwertyuiuoppooiqwurqeiopqww",
            "a=========================a",
        ];
        let expected: [u64; 6] = [3, 1, 27, 3, 0, 2];

        for (g, e) in zip(given, expected) {
            let mut pre = Shannon::new();
            let _ = pre.write(g.as_bytes());
            let _ = pre.shannon();
            assert_eq!(pre.get_occurrence(&b'a'), e);
        }
    }
}
