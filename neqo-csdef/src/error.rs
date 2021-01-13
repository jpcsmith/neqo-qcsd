use std::result;
use std::io;


/// A type alias for `Result<T, flow_shaper::Error>`.
pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(ErrorKind);

impl Error {
    /// A crate private constructor for `Error`.
    pub(crate) fn new(kind: ErrorKind) -> Error {
        Error(kind)
    }

    /// Return the specific type of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    /// Unwrap this error into its underlying type.
    pub fn into_kind(self) -> ErrorKind {
        self.0
    }
}


/// The specific type of an error.
#[derive(Debug)]
pub enum ErrorKind {
    Io(io::Error)
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(ErrorKind::Io(err))
    }
}

impl From<csv::Error> for Error {
    fn from(err: csv::Error) -> Error {
        Error::new(ErrorKind::Io(io::Error::from(err)))
    }
}
