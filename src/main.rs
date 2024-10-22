use std::{io::{Read, Write}, path::PathBuf};
use clap::Parser;
use rsa::{pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey}, pkcs8::{DecodePrivateKey, DecodePublicKey, LineEnding}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(clap::Subcommand, Clone)]
enum Command {
    /// Takes a public key and encrypts the provided file with that key
    Encrypt{
        #[clap(flatten)]
        group: PubInputGroup,

        /// File to write output to (stdout is used if a file isnt provided)
        #[arg(short, long)]
        out_file: Option<PathBuf>,

        /// Format of the output file
        #[arg(short, long, default_value_t = DataFormat::Base64)]
        format: DataFormat,
    },
    /// Takes a private key and decrypts the provided file with that key
    Decrypt{
        #[clap(flatten)]
        group: PrivInputGroup,

        /// File to write output to (stdout is used if a file isnt provided)
        #[arg(short, long)]
        out_file: Option<PathBuf>,

        /// Format of the input file
        #[arg(short, long, default_value_t = DataFormat::Base64)]
        format: DataFormat,
    },
    /// Generates a public key from the private key provided
    GeneratePub{
        /// The private key to generate a public key from (stdin is used if a file isnt provided)
        #[arg(short, long)]
        in_file: Option<PathBuf>,

        /// File to write output to (stdout is used if a file isnt provided)
        #[arg(short, long)]
        out_file: Option<PathBuf>,

        /// Format of the output key
        #[arg(short, long, default_value_t = KeyFormat::PEM)]
        format: KeyFormat,
    },
    /// Generates a private key with the provided bitsize (Be aware, this may take a few seconds)
    GeneratePriv{
        /// The bitsize of the key to generate
        #[arg(short, long, default_value_t = 2048)]
        bit_size: usize,

        /// File to write output to (stdout is used if a file isnt provided)
        #[arg(short, long)]
        out_file: Option<PathBuf>,

        /// Format of the output key
        #[arg(short, long, default_value_t = KeyFormat::PEM)]
        format: KeyFormat,
    },
}
#[derive(clap::Args, Clone)]
#[group(required=true, multiple=true)]
pub struct PrivInputGroup {
        /// Private key to decrypt with (stdin is used if a file isnt provided)
        #[arg(short, long)]
        priv_key: Option<PathBuf>,

        /// File to decrypt (stdin is used if a file isnt provided)
        #[arg(short, long)]
        in_file: Option<PathBuf>,
}
#[derive(clap::Args, Clone)]
#[group(required=true, multiple=true)]
pub struct PubInputGroup {
        /// Public key to encrypt with (stdin is used if a file isnt provided)
        #[arg(short, long)]
        pub_key: Option<PathBuf>, 

        /// File to encrypt (stdin is used if a file isnt provided)
        #[arg(short, long)]
        in_file: Option<PathBuf>,
}
#[derive(clap::ValueEnum, Clone, Copy)]
enum DataFormat {
    Base64,
    Raw,
}
impl ToString for DataFormat {
    fn to_string(&self) -> String {
        match self {
            DataFormat::Base64 => "base64",
            DataFormat::Raw => "raw",
        }.to_string()
    }
}
#[derive(clap::ValueEnum, Clone, Copy)]
enum KeyFormat {
    DER,
    PEM,
}
impl ToString for KeyFormat {
    fn to_string(&self) -> String {
        match self {
            KeyFormat::DER => "der",
            KeyFormat::PEM => "pem",
        }.to_string()
    }
}
fn main() {
    let args = Cli::parse();
    match args.command {
        Command::Encrypt { group, out_file, format } => {
            let mut rng = rand::thread_rng();
            let key = read_pub(reader(group.pub_key));
            let mut input_file = Vec::new();
            reader(group.in_file).read_to_end(&mut input_file).expect("Failed to read from stdin");
            let encrypted_data = key.encrypt(&mut rng, Pkcs1v15Encrypt, &input_file).expect("Failed to encrypt data");
            match format {
                DataFormat::Base64 => base64::write::EncoderWriter::new(writer(out_file), &base64::engine::general_purpose::STANDARD).write_all(&encrypted_data).expect("Failed to encode base64 and write to file/stdout"),
                DataFormat::Raw => writer(out_file).write_all(&encrypted_data).expect("Failed to write to file"),
            }
        },
        Command::Decrypt { group, out_file, format } => {
            let key = read_priv(reader(group.priv_key));
            let mut input_file = Vec::new();

            match format {
                DataFormat::Base64 => base64::read::DecoderReader::new(reader(group.in_file), &base64::engine::general_purpose::STANDARD).read_to_end(&mut input_file).expect("Failed to decode base64 from stdin"),
                DataFormat::Raw => reader(group.in_file).read_to_end(&mut input_file).expect("Failed to read from stdin"),
            };

            let decrypted_data = key.decrypt(Pkcs1v15Encrypt, &input_file).expect("Failed to decrypt data");
            writer(out_file).write_all(&decrypted_data).expect("Failed to write to file/stdout");
        },
        Command::GeneratePub { in_file, out_file, format } => {
            let key = RsaPublicKey::from(read_priv(reader(in_file)));
            writer(out_file).write(&write_pub(key, format)).expect("Failed to write to file/stdout");
        },
        Command::GeneratePriv { bit_size, out_file, format } => {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, bit_size).expect("Failed to generate a key");
            writer(out_file).write(&write_priv(priv_key, format)).expect("Failed to write to file/stdout");
        },
    };
}
fn write_priv(key: RsaPrivateKey, key_format: KeyFormat) -> Vec<u8> {
    match key_format {
        KeyFormat::DER => key.to_pkcs1_der().expect("Failed to convert key to DER").as_bytes().to_vec(),
        KeyFormat::PEM => key.to_pkcs1_pem(LineEnding::LF).expect("Failed to convert key to PEM").as_bytes().to_vec(),
    }
}
fn write_pub(key: RsaPublicKey, key_format: KeyFormat) -> Vec<u8> {
    match key_format {
        KeyFormat::DER => key.to_pkcs1_der().expect("Failed to convert key to DER").as_bytes().to_vec(),
        KeyFormat::PEM => key.to_pkcs1_pem(LineEnding::LF).expect("Failed to convert key to PEM").as_bytes().to_vec(),
    }
}
fn reader(file: Option<PathBuf>) -> Box<dyn Read> {
    match file {
        Some(path) => Box::new(std::fs::OpenOptions::new().read(true).open(path).expect("Failed to open input file")),
        None => Box::new(std::io::stdin()),
    }
}
fn writer(file: Option<PathBuf>) -> Box<dyn Write> {
    match file {
        Some(path) => Box::new(std::fs::OpenOptions::new().write(true).create(true).open(path).expect("Failed to open or create output file")),
        None => Box::new(std::io::stdout()),
    }
}
fn read_priv<R: std::io::Read>(mut reader: R) -> RsaPrivateKey {
    let mut raw_data = Vec::new();
    reader.read_to_end(&mut raw_data).expect("Failed to read key file/stdin");
    let str_data = String::from_utf8_lossy(&raw_data);
    RsaPrivateKey::from_pkcs8_der(&raw_data).unwrap_or_else(|_| {
        RsaPrivateKey::from_pkcs8_pem(&str_data).unwrap_or_else(|_| {
            RsaPrivateKey::from_pkcs1_der(&raw_data).unwrap_or_else(|_| {
                RsaPrivateKey::from_pkcs1_pem(&str_data).expect("Not a supported RSA private key")
            })
        })
    })
}
fn read_pub<R: std::io::Read>(mut reader: R) -> RsaPublicKey {
    let mut raw_data = Vec::new();
    reader.read_to_end(&mut raw_data).expect("Failed to read key file/stdin");
    let str_data = String::from_utf8_lossy(&raw_data);
    RsaPublicKey::from_pkcs1_der(&raw_data).unwrap_or_else(|_| {
        RsaPublicKey::from_pkcs1_pem(&str_data).unwrap_or_else(|_| {
            RsaPublicKey::from_public_key_der(&raw_data).unwrap_or_else(|_| {
                RsaPublicKey::from_public_key_pem(&str_data).unwrap_or_else(|_| {
                    RsaPublicKey::from(RsaPrivateKey::from_pkcs8_der(&raw_data).unwrap_or_else(|_| {
                        RsaPrivateKey::from_pkcs8_pem(&str_data).unwrap_or_else(|_| {
                            RsaPrivateKey::from_pkcs1_der(&raw_data).unwrap_or_else(|_| {
                                RsaPrivateKey::from_pkcs1_pem(&str_data).expect("Not a supported RSA public or private key")
                            })
                        })
                    }))
                })
            })
        })
    })
}
