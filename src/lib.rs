use hmac::{Hmac, Mac};
use std::{
    borrow::Cow,
    collections::HashMap,
    str::FromStr,
    time::{Duration, SystemTime},
};
use url::Url;

const OTP_SCHEME: &str = "otpauth";
const EVENT_TYPE: &str = "hotp";
const TIME_TYPE: &str = "totp";
const SECRET_PARAM: &str = "secret";
const ALGORITHM_PARAM: &str = "algorithm";
const DIGITS_PARAM: &str = "digits";
const COUNTER_PARAM: &str = "counter";
const PERIOD_PARAM: &str = "period";

const SECRET_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported scheme: '{0}'")]
    UnsupportedScheme(String),

    #[error("unsupported password type: '{0}'")]
    UnsupportedPasswordType(String),

    #[error("unsupported algorithm: '{0}'")]
    UnsupportedAlgorithm(String),

    #[error("unsupported number of digits: '{0}'")]
    UnsupportedDigits(String),

    #[error("missing password type")]
    MissingPasswordType,

    #[error("missing secret value")]
    MissingSecretValue,

    #[error("missing counter value")]
    MissingCounterValue,

    #[error("could not decode secret")]
    FailedDecodingSecret,

    #[error("could not parse integer value")]
    FailedParsingValue(#[from] std::num::ParseIntError),

    #[error("could not decode url encoded value")]
    FailedDecodingUrlEncodedString(#[from] std::string::FromUtf8Error),

    #[error("the shared secret is the wrong length")]
    InvalidSecretLength(#[from] digest::InvalidLength),
}

#[derive(Debug)]
pub struct Otp {
    hash: Hash,
    digits: Digits,
    counter: Counter,
}

impl Otp {
    fn password_for_counter(&self, count: u64) -> String {
        self.digits.format(self.hash.code(count))
    }

    pub fn next_password(&mut self) -> String {
        let counter = self.counter.next_count();
        self.password_for_counter(counter)
    }

    pub fn next_password_and_expire_time(&mut self) -> (String, Option<SystemTime>) {
        let (counter, expire) = self.counter.next_count_and_expire_time();
        let password = self.password_for_counter(counter);
        (password, expire)
    }

    pub fn metadata(url: &Url) -> Result<Vec<(String, String)>, Error> {
        if OTP_SCHEME != url.scheme() {
            return Err(Error::UnsupportedScheme(url.scheme().into()));
        }

        let kind = match url.domain() {
            Some(EVENT_TYPE) => "event",
            Some(TIME_TYPE) => "time",
            Some(x) => return Err(Error::UnsupportedPasswordType(x.into())),
            None => return Err(Error::MissingPasswordType),
        };
        let mut meta = vec![
            ("type".to_string(), kind.to_string()),
            (
                "label".to_string(),
                urlencoding::decode(url.path().trim_matches('/'))?.to_string(),
            ),
        ];

        meta.extend(
            url.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string())),
        );

        Ok(meta)
    }

    pub fn load(url: &Url) -> Result<Self, Error> {
        if OTP_SCHEME != url.scheme() {
            return Err(Error::UnsupportedScheme(url.scheme().into()));
        }

        let mut query: HashMap<_, _> = url.query_pairs().collect();
        let counter = match url.domain() {
            Some(EVENT_TYPE) => {
                let count = query
                    .remove(COUNTER_PARAM)
                    .ok_or(Error::MissingCounterValue)?
                    .parse()?;
                Counter::Event { count }
            }
            Some(TIME_TYPE) => {
                let period = query
                    .remove(PERIOD_PARAM)
                    .map(|p| p.parse())
                    .unwrap_or(Ok(30))?;
                Counter::Time { period }
            }
            Some(x) => return Err(Error::UnsupportedPasswordType(x.into())),
            None => return Err(Error::MissingPasswordType),
        };
        let digits = query
            .remove(DIGITS_PARAM)
            .map(|d| d.parse())
            .unwrap_or(Ok(Digits::Six))?;
        let secret = query
            .remove(SECRET_PARAM)
            .ok_or(Error::MissingSecretValue)?;
        let secret = base32::decode(SECRET_ALPHABET, &secret).ok_or(Error::FailedDecodingSecret)?;
        let algorithm = query
            .remove(ALGORITHM_PARAM)
            .unwrap_or(Cow::Borrowed("sha1"));
        let hash = Hash::new(&algorithm, &secret)?;

        Ok(Self {
            hash,
            digits,
            counter,
        })
    }

    pub fn save(&self, url: &mut Url) -> bool {
        self.counter.save(url)
    }
}

#[derive(Debug)]
pub enum Hash {
    Sha1(Hmac<sha1::Sha1>),
    Sha256(Hmac<sha2::Sha256>),
    Sha512(Hmac<sha2::Sha512>),
}

impl Hash {
    fn new(algorithm: &str, secret: &[u8]) -> Result<Self, Error> {
        match algorithm.trim().to_lowercase().as_str() {
            "sha-1" | "sha1" => Ok(Self::Sha1(Hmac::new_from_slice(secret)?)),
            "sha-256" | "sha256" => Ok(Self::Sha256(Hmac::new_from_slice(secret)?)),
            "sha-512" | "sha512" => Ok(Self::Sha512(Hmac::new_from_slice(secret)?)),
            x => Err(Error::UnsupportedAlgorithm(x.into())),
        }
    }

    fn code(&self, count: u64) -> u32 {
        match self {
            Self::Sha1(mac) => Self::generate_code(mac, count),
            Self::Sha256(mac) => Self::generate_code(mac, count),
            Self::Sha512(mac) => Self::generate_code(mac, count),
        }
    }

    fn generate_code<M: Mac + Clone>(mac: &M, count: u64) -> u32 {
        let mac: M = mac.clone();
        let data = count.to_be_bytes();

        let hash = mac.chain_update(data).finalize().into_bytes();
        let len = hash.len();
        let idx = (0x0f & hash[len - 1]) as usize;

        (((0x7f & hash[idx]) as u32) << 24)
            | ((hash[idx + 1] as u32) << 16)
            | ((hash[idx + 2] as u32) << 8)
            | (hash[idx + 3] as u32)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Digits {
    Six,   // 19.9 bits
    Seven, // 23.3 bits
    Eight, // 26.6 bits
    Nine,  // 29.9 bits
           // Ten,    // 33.2 bits
}

impl Digits {
    pub fn format(&self, value: u32) -> String {
        match self {
            Self::Six => format!("{:06}", value % 1_000_000),
            Self::Seven => format!("{:07}", value % 10_000_000),
            Self::Eight => format!("{:08}", value % 100_000_000),
            Self::Nine => format!("{:09}", value % 1_000_000_000),
        }
    }
}

impl FromStr for Digits {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "6" => Ok(Self::Six),
            "7" => Ok(Self::Seven),
            "8" => Ok(Self::Eight),
            "9" => Ok(Self::Nine),
            x => Err(Error::UnsupportedDigits(x.into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Counter {
    Event { count: u64 },
    Time { period: u64 },
}

impl Counter {
    fn save(&self, url: &mut Url) -> bool {
        match self {
            Self::Event { count } => {
                #[allow(clippy::needless_collect)]
                let new: Vec<_> = url
                    .query_pairs()
                    .map(|(k, v)| {
                        if k == COUNTER_PARAM {
                            (k.to_string(), count.to_string())
                        } else {
                            (k.to_string(), v.to_string())
                        }
                    })
                    .collect();

                url.query_pairs_mut().clear().extend_pairs(new.into_iter());
                true
            }
            _ => false,
        }
    }

    fn next_count(&mut self) -> u64 {
        match self {
            Self::Event { count } => bump_counter(count),
            Self::Time { period } => time_to_counter(SystemTime::now(), *period),
        }
    }

    fn next_count_and_expire_time(&mut self) -> (u64, Option<SystemTime>) {
        match self {
            Self::Event { count } => (bump_counter(count), None),
            Self::Time { period } => {
                let now = SystemTime::now();
                let counter = time_to_counter(now, *period);
                let expire = counter_expires(counter, *period);
                (counter, Some(expire))
            }
        }
    }
}

fn bump_counter(count: &mut u64) -> u64 {
    let old = *count;
    *count += 1;
    old
}

fn time_to_counter(time: SystemTime, period: u64) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() / period)
        .expect("time moves forward")
}

fn counter_expires(counter: u64, period: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs((counter + 1) * period)
}

#[cfg(test)]
mod tests {
    use super::{counter_expires, time_to_counter, Counter, Digits, Hash, Otp};
    use std::time::{Duration, SystemTime};
    use url::Url;

    fn unix_time_to_system_time(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn totp_load_url() {
        let url = Url::parse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30").expect("valid url");
        let otp = Otp::load(&url).expect("to parse");
        assert!(matches!(otp.hash, Hash::Sha1(_)));
        assert_eq!(otp.digits, Digits::Six);
        assert_eq!(otp.counter, Counter::Time { period: 30 });
    }

    #[test]
    fn hotp_load_url() {
        let url = Url::parse("otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&counter=12345").expect("valid url");
        let otp = Otp::load(&url).expect("valid");
        assert!(matches!(otp.hash, Hash::Sha1(_)));
        assert_eq!(otp.digits, Digits::Six);
        assert_eq!(otp.counter, Counter::Event { count: 12345 });
    }

    #[test]
    fn totp_load_url_example() {
        let url = Url::parse("otpauth://totp/Test%20Inc.:fred%40example.com?secret=fvcamutxjsuszoylk7kdez6pcua3yfcvtgmk5eufqzxmajqejpuoqvzc&algorithm=SHA256&digits=9&period=15&lock=false").expect("valid url");
        let otp = Otp::load(&url).expect("to parse");
        assert!(matches!(otp.hash, Hash::Sha256(_)));
        assert_eq!(otp.digits, Digits::Nine);
        assert_eq!(otp.counter, Counter::Time { period: 15 });
    }

    #[test]
    fn time_to_counter_example_from_rfc_6238() {
        let test = |time: u64, count: u64| {
            assert_eq!(time_to_counter(unix_time_to_system_time(time), 30), count)
        };

        test(59, 0x00000001);
        test(1111111109, 0x023523EC);
        test(1111111111, 0x023523ED);
        test(1234567890, 0x0273EF07);
        test(2000000000, 0x03F940AA);
        test(20000000000, 0x27BC86AA);
    }

    #[test]
    fn counter_expires_example_from_rfc_6238() {
        let test = |counter, time| {
            assert_eq!(counter_expires(counter, 30), unix_time_to_system_time(time));
        };

        test(0x00000001, 60);
        test(0x023523EC, 1111111110);
        test(0x023523ED, 1111111140);
        test(0x0273EF07, 1234567920);
        test(0x03F940AA, 2000000010);
        test(0x27BC86AA, 20000000010);
    }

    fn test_password(algorithm: &str, secret: &str, digits: Digits) -> impl Fn(u64, &str) {
        let secret = hex::decode(secret).expect("valid hex data");
        let hash = Hash::new(algorithm, &secret).expect("valid secret");

        move |counter, password| {
            assert_eq!(digits.format(hash.code(counter)), password);
        }
    }

    #[test]
    fn example_form_rfc_4226() {
        let test = test_password(
            "sha-1",
            "3132333435363738393031323334353637383930",
            Digits::Six,
        );
        test(0, "755224");
        test(0, "755224");
        test(1, "287082");
        test(2, "359152");
        test(3, "969429");
        test(4, "338314");
        test(5, "254676");
        test(6, "287922");
        test(7, "162583");
        test(8, "399871");
        test(9, "520489");
    }

    #[test]
    fn example_from_rfc_6238_sha1() {
        let test = test_password(
            "Sha1",
            "3132333435363738393031323334353637383930",
            Digits::Eight,
        );
        test(0x00000001, "94287082");
        test(0x023523EC, "07081804");
        test(0x023523ED, "14050471");
        test(0x0273EF07, "89005924");
        test(0x03F940AA, "69279037");
        test(0x27BC86AA, "65353130");
    }

    #[test]
    fn example_from_rfc_6238_sha256() {
        let test = test_password(
            "Sha256",
            "3132333435363738393031323334353637383930313233343536373839303132",
            Digits::Eight,
        );
        test(0x00000001, "46119246");
        test(0x023523EC, "68084774");
        test(0x023523ED, "67062674");
        test(0x0273EF07, "91819424");
        test(0x03F940AA, "90698825");
        test(0x27BC86AA, "77737706");
    }

    #[test]
    fn counter_example_from_rfc_6238_sha512() {
        let test = test_password("sha512", "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334", Digits::Eight);
        test(0x00000001, "90693936");
        test(0x023523EC, "25091201");
        test(0x023523ED, "99943326");
        test(0x0273EF07, "93441116");
        test(0x03F940AA, "38618901");
        test(0x27BC86AA, "47863826");
    }
}
