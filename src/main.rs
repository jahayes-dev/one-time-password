use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305 as Cipher, Key, Nonce,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::SystemTime,
};
use url::Url;

use one_time_password::OTP;

const FILE_MAGIC: &[u8; 20] = b"one-time-password-v1";
const SERVICE: &str = "com.code-spelunking.one-time-password.file-key";
const USER: &str = "command-line";

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("failed file io")]
    IO(#[from] std::io::Error),

    #[error("failed atomic save")]
    FailedAtomicSave(#[from] tempfile::PersistError),

    #[error("bad file magic")]
    BadFileMagic,

    #[error("failed deserialization")]
    FailedDeserialization(#[from] rmp_serde::decode::Error),

    #[error("failed serialization")]
    FailedSerialization(#[from] rmp_serde::encode::Error),

    #[error("missing item")]
    MissingItem,

    #[error("key chain error")]
    KeyChain(#[from] keyring::Error),

    #[error("failed decoding file key")]
    FailedDecodingFileKey(#[from] base64::DecodeError),

    #[error("invalid file key length")]
    InvalidFileKeyLength,

    #[error("failed encrypting password file")]
    FailedEncryptingFile,

    #[error("failed decrypting password file")]
    FailedDecryptingFile,

    #[error("failed parsing url")]
    FailedParsingUrl(#[from] url::ParseError),

    #[error("could not load image")]
    FailedLoadingImage(#[from] image::ImageError),

    #[error("could not load image")]
    FailedDecodingImage(#[from] rqrr::DeQRError),

    #[error("could not find a otpauth:// url")]
    MissingOtpAuthUrl,

    #[error("one time password error")]
    OTP(#[from] one_time_password::Error),
}

#[derive(Debug, Clone)]
struct FileKey(Key);
impl FromStr for FileKey {
    type Err = Error;
    fn from_str(b64: &str) -> Result<Self, Error> {
        let key = STANDARD.decode(b64.trim())?;
        let key = Key::from_exact_iter(key.into_iter()).ok_or(Error::InvalidFileKeyLength)?;
        Ok(FileKey(key))
    }
}

impl FileKey {
    fn load() -> Result<Self, Error> {
        let entry = keyring::Entry::new(SERVICE, USER)?;
        match entry.get_password() {
            Ok(key) => Self::from_str(key.as_str()),
            Err(keyring::Error::NoEntry) => {
                let key = Cipher::generate_key(&mut OsRng);
                let b64 = STANDARD.encode(key);
                entry.set_password(&b64)?;
                Ok(FileKey(key))
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Payload {
    items: BTreeMap<String, Url>,
}

impl Payload {
    fn new() -> Self {
        Self {
            items: BTreeMap::new(),
        }
    }

    fn delete(&mut self, key: impl AsRef<str>) -> bool {
        self.items.remove(key.as_ref()).is_some()
    }

    fn metadata(&self, key: impl AsRef<str>) -> Result<bool, Error> {
        let url = self.items.get(key.as_ref()).ok_or(Error::MissingItem)?;
        for (key, mut value) in OTP::metadata(url)? {
            if key == "secret" {
                value = "*".repeat(value.len())
            }
            println!("{key:12}: {value}");
        }
        Ok(false)
    }

    fn password(&mut self, key: impl AsRef<str>, poll: bool) -> Result<bool, Error> {
        let url = self.items.get_mut(key.as_ref()).ok_or(Error::MissingItem)?;

        let mut otp = OTP::load(url)?;
        loop {
            let (pass, expires) = otp.next_password_and_expire_time();
            println!("{}", pass);

            if let (true, Some(expires)) = (poll, expires) {
                if let Ok(dur) = expires.duration_since(SystemTime::now()) {
                    std::thread::sleep(dur);
                }
                continue;
            }
            break;
        }

        Ok(otp.save(url))
    }

    fn keys(&self) -> bool {
        for name in self.items.keys() {
            println!("    {name}");
        }
        false
    }

    fn stdin(&mut self, key: impl Into<String>) -> Result<bool, Error> {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        let url = Url::parse(input.trim())?;
        self.items.insert(key.into(), url);
        Ok(true)
    }

    fn qr_code(&mut self, key: impl Into<String>, path: impl AsRef<Path>) -> Result<bool, Error> {
        let url = read_qr_code(path.as_ref())?;
        self.items.insert(key.into(), url);
        Ok(true)
    }

    fn load(path: &Path, key: &FileKey) -> Result<Self, Error> {
        let cipher = Cipher::new(&key.0);

        let file = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(file);

        let mut magic = *FILE_MAGIC;
        reader.read_exact(&mut magic)?;
        if magic != *FILE_MAGIC {
            return Err(Error::BadFileMagic);
        }

        let mut nonce = Nonce::default();
        reader.read_exact(&mut nonce)?;

        let mut cipher_text = Vec::new();
        reader.read_to_end(&mut cipher_text)?;

        let payload = cipher
            .decrypt(&nonce, cipher_text.as_slice())
            .map_err(|_| Error::FailedDecryptingFile)?;

        Ok(rmp_serde::from_slice(&payload)?)
    }

    fn save(&self, path: &Path, key: &FileKey) -> Result<(), Error> {
        let cipher = Cipher::new(&key.0);

        let dir = path.parent().expect("absolute path");
        std::fs::create_dir_all(dir)?;

        // do an atomic save -- first write to a temp then rename it.
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        file.write_all(FILE_MAGIC)?;

        let nonce = Cipher::generate_nonce(&mut OsRng);
        file.write_all(&nonce)?;

        let payload = rmp_serde::to_vec_named(self)?;
        let cipher_text = cipher
            .encrypt(&nonce, payload.as_slice())
            .map_err(|_| Error::FailedEncryptingFile)?;
        file.write_all(&cipher_text)?;

        // rename the file while is atomic at the file system level.
        file.persist(path)?;
        Ok(())
    }
}

fn read_qr_code(path: impl AsRef<Path>) -> Result<Url, Error> {
    let img = image::open(path)?.into_luma8();
    let mut img = rqrr::PreparedImage::prepare(img);
    for grids in img.detect_grids() {
        let (_, content) = grids.decode()?;
        println!("content: {content}");
        match Url::parse(&content) {
            Ok(url) if url.scheme() == "otpauth" => return Ok(url),
            _ => println!("not a otpauth:// url: {content}"),
        }
    }

    Err(Error::MissingOtpAuthUrl)
}

fn default_file() -> PathBuf {
    home::home_dir()
        .expect("HOME")
        .join(".config/one-time-password/db")
}

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Override password file path
    #[arg(long, default_value_os_t = default_file(), env = "ONE_TIME_PASSWORD_FILE", hide_env=true)]
    file: PathBuf,

    /// Override encryption key for the password file [default: value in key chain]
    #[arg(long, value_parser=FileKey::from_str, env="ONE_TIME_PASSWORD_KEY", hide_env=true)]
    key: Option<FileKey>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Display the next one time password
    #[command(alias = "pass")]
    Password {
        /// Password name
        name: String,
        /// Display a new one time password after it expires
        #[arg(long, short)]
        poll: bool,
    },
    /// Display password name
    List,
    /// Display password metadata
    Get {
        /// Password name
        name: String,
    },
    /// Add or update a password by reading a otpauth:// url from stdin
    Set {
        /// Password name
        name: String,
    },
    /// Add or update a password by loading a QR code
    QRCode {
        /// Password name
        name: String,

        /// Path to QR code image
        image: PathBuf,
    },

    /// Delete a password
    Delete {
        /// Password name
        name: String,
    },
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let key = cli.key.map(Ok).unwrap_or_else(FileKey::load)?;

    let mut payload = if cli.file.exists() {
        Payload::load(&cli.file, &key)?
    } else {
        Payload::new()
    };

    let dirty = match cli.command {
        Commands::Password { name, poll } => payload.password(name, poll)?,
        Commands::List => payload.keys(),
        Commands::Get { name } => payload.metadata(name)?,
        Commands::Set { name } => payload.stdin(name)?,
        Commands::QRCode { name, image } => payload.qr_code(name, image)?,
        Commands::Delete { name } => payload.delete(name),
    };

    if dirty {
        payload.save(&cli.file, &key)?;
    }

    Ok(())
}
