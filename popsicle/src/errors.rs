/// Errors produced by the private set intersection protocols.
#[derive(Debug)]
pub enum Error {
    /// Coin tossing failed.
    CoinTossError(scuttlebutt::cointoss::Error),
    /// The underlying oblivious PRF failed.
    OprfError(ocelot::Error),
    /// An input/output error occurred.
    IoError(std::io::Error),
    /// The cuckoo hash is full.
    CuckooHashFull,
    /// The provided cuckoo hash set size is invalid.
    InvalidCuckooSetSize(usize),
    /// The provided cuckoo hash parameters are invalid.
    InvalidCuckooParameters {
        /// Number of items.
        nitems: usize,
        /// Number of hashes.
        nhashes: usize,
    },
    /// An error occurred in the PSI protocol.
    PsiProtocolError(String),
    /// Not enough payloads.
    InvalidPayloadsLength,
    /// SSL Error
    #[cfg(feature = "psty")]
    SSLError(openssl::error::ErrorStack),
    /// An error occurred in the underlying 2PC protocol.
    #[cfg(feature = "psty")]
    TwopacError(fancy_garbling::errors::TwopacError),
}

#[cfg(feature = "psty")]
impl From<openssl::error::ErrorStack> for Error {
    #[inline]
    fn from(e: openssl::error::ErrorStack) -> Error {
        Error::SSLError(e)
    }
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<ocelot::Error> for Error {
    #[inline]
    fn from(e: ocelot::Error) -> Error {
        Error::OprfError(e)
    }
}

impl From<scuttlebutt::cointoss::Error> for Error {
    #[inline]
    fn from(e: scuttlebutt::cointoss::Error) -> Error {
        Error::CoinTossError(e)
    }
}

#[cfg(feature = "psty")]
impl From<fancy_garbling::errors::TwopacError> for Error {
    #[inline]
    fn from(e: fancy_garbling::errors::TwopacError) -> Error {
        Error::TwopacError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::CoinTossError(e) => write!(f, "coin toss error: {}", e),
            Error::OprfError(e) => write!(f, "oblivious PRF error: {}", e),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::CuckooHashFull => write!(f, "cuckoo hash error: table is full"),
            Error::InvalidCuckooSetSize(n) => {
                write!(f, "cuckoo hash error: invalid set size {}", n)
            }
            Error::InvalidCuckooParameters { nitems, nhashes } => write!(
                f,
                "cuckoo hash error: no parameters set for {} items and {} hashes",
                nitems, nhashes
            ),
            Error::PsiProtocolError(s) => write!(f, "PSI protocol error: {}", s),
            Error::InvalidPayloadsLength => write!(f, "Invalid length of payloads!"),
            #[cfg(feature = "psty")]
            Error::SSLError(e) => write!(f, "SSL Error: {}", e),
            #[cfg(feature = "psty")]
            Error::TwopacError(e) => write!(f, "2PC protocol error: {}", e),
        }
    }
}
