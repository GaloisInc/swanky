/**
Error type specific to Diet Mac'n'Cheese and wrapping up other errors.

This enum has the errors specific to Diet Mac'n'Cheese and also wraps up other errors from
components like `std::io` and `ocelot`.
*/
#[derive(Debug)]
pub enum Error {
    /// Error specific to HomCom
    HomcomError(String),
    /// Error specific to Diet Mac'n'Cheese.
    BackendError(String),
    /// Error specific to edabits.
    EdabitsError(String),
    /// An I/O error has occurred.
    IoError(std::io::Error),
    /// An Ocelot error has occurred.
    OcelotError(ocelot::Error),
    /// Error from `eyre` (eventually will replace this)
    EyreError(eyre::Error),
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<ocelot::Error> for Error {
    fn from(e: ocelot::Error) -> Error {
        Error::OcelotError(e)
    }
}

impl From<eyre::Error> for Error {
    fn from(e: eyre::Error) -> Error {
        Error::EyreError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::HomcomError(s) => write!(f, "homcom error: {}", s),
            Error::BackendError(s) => write!(f, "backend error: {}", s),
            Error::EdabitsError(s) => write!(f, "edabits error: {}", s),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::OcelotError(e) => write!(f, "Ocelot error: {}", e),
            Error::EyreError(e) => write!(f, "Error: {}", e),
        }
    }
}

/**
Result type specific to Diet Mac'n'Cheese.

This `Result` type is specializing `std::result::Result` with `Error`.
*/
pub type Result<T> = std::result::Result<T, Error>;
