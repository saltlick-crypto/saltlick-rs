use saltlick::{read::SaltlickDecrypter, write::SaltlickEncrypter};
use std::{
    error::Error,
    io::{Cursor, Read, Write},
};

fn main() -> Result<(), Box<dyn Error>> {
    // Generate a new public/secret keypair
    let (public, secret) = saltlick::gen_keypair();

    // Writing data to a stream
    let writer = Vec::new();
    let mut stream = SaltlickEncrypter::new(public.clone(), writer);
    stream.write_all(b"I have a secret for you")?;
    let ciphertext = stream.finalize()?;

    // Reading data back from stream
    let reader = Cursor::new(ciphertext);
    let mut stream = SaltlickDecrypter::new(public, secret, reader);
    let mut output = String::new();
    stream.read_to_string(&mut output)?;
    assert_eq!("I have a secret for you", output);

    Ok(())
}
