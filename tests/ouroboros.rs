// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use rand::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use saltlick::{bufread, gen_keypair, read, write};
use std::io::{self, Cursor};

fn random_bytes(seed: u64, size: usize) -> Box<[u8]> {
    let mut rng = XorShiftRng::seed_from_u64(seed);
    let mut bytes = vec![0u8; size];
    rng.fill_bytes(&mut bytes);
    bytes.into_boxed_slice()
}

#[test]
fn ouroboros_test() {
    let random_data = random_bytes(0, 10 * 1024 * 1024);
    let (public_key, secret_key) = gen_keypair();

    let encrypt_bufreader =
        bufread::SaltlickEncrypter::new(public_key.clone(), Cursor::new(random_data.clone()));
    let mut encrypt_reader = read::SaltlickEncrypter::new(public_key.clone(), encrypt_bufreader);
    let mut encrypt_writer = write::SaltlickEncrypter::new(public_key.clone(), Vec::new());
    io::copy(&mut encrypt_reader, &mut encrypt_writer).unwrap();
    let super_ciphertext = encrypt_writer.finalize().unwrap();

    let decrypt_bufreader = bufread::SaltlickDecrypter::new(
        public_key.clone(),
        secret_key.clone(),
        Cursor::new(super_ciphertext),
    );
    let mut decrypt_reader =
        read::SaltlickDecrypter::new(public_key.clone(), secret_key.clone(), decrypt_bufreader);
    let mut decrypt_writer = write::SaltlickDecrypter::new(public_key, secret_key, Vec::new());
    io::copy(&mut decrypt_reader, &mut decrypt_writer).unwrap();
    let super_plaintext = decrypt_writer.finalize().unwrap();

    assert_eq!(&random_data[..], &super_plaintext[..]);
}
