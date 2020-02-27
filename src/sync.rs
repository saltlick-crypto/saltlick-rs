// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(test)]
mod tests {
    use crate::{key::gen_keypair, read::SaltlickDecrypter, write::SaltlickEncrypter};
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{
        cmp,
        io::{Cursor, Read, Write},
        iter,
    };

    fn random_bytes(seed: u64, size: usize) -> Box<[u8]> {
        let mut rng = XorShiftRng::seed_from_u64(seed);
        let mut bytes = vec![0u8; size];
        rng.fill_bytes(&mut bytes);
        bytes.into_boxed_slice()
    }

    #[test]
    fn single_write_test() {
        for size in &[
            1,
            10 * 1024,
            32 * 1024,
            100 * 1024,
            200 * 1024,
            10 * 1024 * 1024,
        ] {
            let random_data = random_bytes(0, *size);
            let (public_key, secret_key) = gen_keypair();
            let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Vec::new());
            encrypter.write_all(&random_data[..]).unwrap();
            let ciphertext = Cursor::new(encrypter.finalize().unwrap());
            let mut decrypter =
                SaltlickDecrypter::new(public_key.clone(), secret_key.clone(), ciphertext);
            let mut output = Vec::new();
            decrypter.read_to_end(&mut output).unwrap();
        }
    }

    #[test]
    fn multiple_write_test() {
        for size in &[
            1,
            10 * 1024,
            32 * 1024,
            100 * 1024,
            200 * 1024,
            10 * 1024 * 1024,
        ] {
            let random_data = random_bytes(0, *size);
            let (public_key, secret_key) = gen_keypair();
            let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Vec::new());
            encrypter.block_size(16 * 1024);
            let mut written = 0;
            // Take increasing chunks so we're varying chunk size.
            for take in iter::successors(Some(1usize), |n| Some(n + 7)) {
                let end = cmp::min(written + take, *size);
                encrypter.write_all(&random_data[written..end]).unwrap();
                written += take;
                if written >= *size {
                    break;
                }
            }
            let ciphertext = Cursor::new(encrypter.finalize().unwrap());
            let mut decrypter =
                SaltlickDecrypter::new(public_key.clone(), secret_key.clone(), ciphertext);
            let mut output = Vec::new();
            decrypter.read_to_end(&mut output).unwrap();
        }
    }

    #[test]
    fn corrupt_value_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).unwrap();
        let mut ciphertext = encrypter.finalize().unwrap();

        // Inject a single bad byte near the end of the stream
        let index = ciphertext.len() - 5;
        ciphertext[index] = ciphertext[index].wrapping_add(1);

        let mut decrypter = SaltlickDecrypter::new(public_key, secret_key, Cursor::new(ciphertext));
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).is_err());
    }

    #[test]
    fn incomplete_stream_test() {
        let random_data = random_bytes(0, 100 * 1024);
        let (public_key, secret_key) = gen_keypair();
        let mut encrypter = SaltlickEncrypter::new(public_key.clone(), Vec::new());
        encrypter.write_all(&random_data[..]).unwrap();
        let mut ciphertext = encrypter.finalize().unwrap();

        // Remove a few bytes from the end
        ciphertext.resize(ciphertext.len() - 5, 0);

        let mut decrypter = SaltlickDecrypter::new(public_key, secret_key, Cursor::new(ciphertext));
        let mut output = Vec::new();
        assert!(decrypter.read_to_end(&mut output).is_err());
    }
}
