use saltlick::{read::AsyncSaltlickDecrypter, write::AsyncSaltlickEncrypter};
use std::error::Error;
use tempdir::TempDir;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Generate a new public/secret keypair
    let (public, secret) = saltlick::gen_keypair();

    let tmp_dir = TempDir::new("saltlick-async")?;
    let file_path = tmp_dir.path().join("secretfile.enc");

    // Writing data to a file asynchronously
    let file_writer = File::create(&file_path).await?;
    let mut stream = AsyncSaltlickEncrypter::new(public.clone(), file_writer);
    stream.write_all(b"I have a secret for you").await?;

    // Ensure all data is flushed to filesystem
    stream.shutdown().await?;

    // Reading data back from file asynchronously
    let file_reader = File::open(&file_path).await?;
    let mut stream = AsyncSaltlickDecrypter::new(public.clone(), secret.clone(), file_reader);
    let mut output = String::new();
    let _ = stream.read_to_string(&mut output).await?;
    assert_eq!("I have a secret for you", output);

    Ok(())
}
