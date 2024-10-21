use std::{fs::write, io::{Read, Write}, path::PathBuf};

use clap::{Arg, Args, Parser};
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey}, pkcs8::{DecodePrivateKey, DecodePublicKey, LineEnding}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Subcommand, Clone)]
enum Command {
    /// Takes a public key and encrypts the provided file with that key, if no file is provided,
    /// stdin is used
    Encrypt{
        /// Public key to encrypt with
        #[arg(short, long)]
        pub_key: PathBuf, 
        /// File to encrypt (stdin is used if a file isnt provided)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// File to write output to, if no file is provided,
    /// stdin is used
        #[arg(short, long)]
        out_file: Option<PathBuf>,
    },
    /// Takes a private key and decrypts the provided file with that key, if no file is provided,
    /// stdin is used
    Decrypt{
        /// Private key to decrypt with
        #[arg(short, long)]
        priv_key: PathBuf,
        /// File to decrypt (stdin is used if a file isnt provided)
        #[arg(short, long)]
        file: Option<PathBuf>,
        /// File to write output to, if no file is provided,
    /// stdin is used

        #[arg(short, long)]
        out_file: Option<PathBuf>,
    },
    /// Generates a public key from the private key provided
    GeneratePub{
        /// The private key to generate a public key from
        #[arg(short, long)]
        priv_key: PathBuf,
        /// File to write output to
        #[arg(short, long)]
        out_file: PathBuf,
    },
    /// Generates a private key with the provided bitsize (Be aware, this may take a few seconds)
    GeneratePriv{
        /// The bitsize of the key to generate
        #[arg(short, long, default_value_t = 2048)]
        bit_size: usize,
        /// File to write output to
        #[arg(short, long)]
        out_file: PathBuf,
    },
}
fn main() {
    let args = Cli::parse();
    match args.command {
        Command::Encrypt { pub_key, file, out_file } => {
            let mut rng = rand::thread_rng();
            let key = read_public_key(pub_key);
            let encrypted_data = match file {
                Some(file) => {
                    let input_file = std::fs::read(&file).expect("Failed to read from file");
                    key.encrypt(&mut rng, Pkcs1v15Encrypt, &input_file)
                },
                None => {
                    let mut input_file = Vec::new();
                    std::io::stdin().read_to_end(&mut input_file).expect("Failed to read from stdin");
                    key.encrypt(&mut rng, Pkcs1v15Encrypt, &input_file)
                },
            }.expect("Failed to encrypt data");

            match out_file {
                Some(file) => {
                    std::fs::write(file, encrypted_data)
                },
                None => {
                    std::io::stdout().write_all(&encrypted_data)
                },
            }.expect("Failed to write to file");
        },
        Command::Decrypt { priv_key, file, out_file } => {
            let mut rng = rand::thread_rng();
            let key = read_private_key(priv_key);
            let decrypted_data = match file {
                Some(file) => {
                    let input_file = std::fs::read(&file).expect("Failed to read from file");
                    key.decrypt(Pkcs1v15Encrypt, &input_file)
                },
                None => {
                    let mut input_file = Vec::new();
                    std::io::stdin().read_to_end(&mut input_file).expect("Failed to read from stdin");
                    key.decrypt(Pkcs1v15Encrypt, &input_file)
                },
            }.expect("Failed to decrypt data");

            match out_file {
                Some(file) => {
                    std::fs::write(file, decrypted_data)
                },
                None => {
                    std::io::stdout().write_all(&decrypted_data)
                },
            }.expect("Failed to write to file");
        },
        Command::GeneratePub { priv_key, out_file } => {
            RsaPublicKey::from(read_private_key(priv_key)).write_pkcs1_pem_file(out_file, LineEnding::LF).expect("Failed to write to file")
        },
        Command::GeneratePriv { bit_size, out_file } => {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, bit_size).expect("Failed to generate a key");
            priv_key.write_pkcs1_pem_file(out_file, LineEnding::LF).expect("Failed to write to file")
        },
    };
}
fn read_private_key<P: AsRef<std::path::Path>>(path: P) -> RsaPrivateKey {
    RsaPrivateKey::read_pkcs8_der_file(&path).unwrap_or_else(|_| {
        RsaPrivateKey::read_pkcs8_pem_file(&path).unwrap_or_else(|_| {
            RsaPrivateKey::read_pkcs1_der_file(&path).unwrap_or_else(|_| {
                RsaPrivateKey::read_pkcs1_pem_file(&path).expect("Not a supported RSA private key")
            })
        })
    })
}
fn read_public_key<P: AsRef<std::path::Path>>(path: P) -> RsaPublicKey {
    RsaPublicKey::read_pkcs1_der_file(&path).unwrap_or_else(|_| {
        RsaPublicKey::read_pkcs1_pem_file(&path).unwrap_or_else(|_| {
            RsaPublicKey::read_public_key_der_file(&path).unwrap_or_else(|_| {
                RsaPublicKey::read_public_key_pem_file(&path).expect("Not a supported RSA public key")
            })
        })
    })
}
    //    let pub_key = RsaPublicKey::from(&priv_key);
    //println!("Hello, world!");
    //
    //// Encrypt
    //let data = b"hello world";
    //let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
    //assert_ne!(&data[..], &enc_data[..]);
    //
    //// Decrypt
    //let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
    //assert_eq!(&data[..], &dec_data[..]);
