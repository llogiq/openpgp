use std;
use openssl;
use algorithm::*;

#[derive(Debug)]
pub enum Error {
    IndexOutOfBounds,
    UnknownSignatureVersion(u8),
    IO(std::io::Error),
    OpenSSL(openssl::ssl::error::SslError),
    Utf8(std::str::Utf8Error),
    InvalidSignature,
    UnknownTag,
    UnsupportedPublicKey(PublicKeyAlgorithm),
    UnsupportedHash(HashAlgorithm),
    NoPublicKey,
    UnknownPublicKey(u8),
    UnknownSubpacketType(u8),
    UnknownPublicKeyAlgorithm(u8),
    UnknownSymmetricKeyAlgorithm(u8),
    UnknownHashAlgorithm(u8),
    UnknownCompressionAlgorithm(u8),
    UnknownSignatureType(u8),
    UnknownRevocationCode(u8),
    NoSessionKey
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IO(e)
    }
}
impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf8(e)
    }
}
impl From<openssl::ssl::error::SslError> for Error {
    fn from(e: openssl::ssl::error::SslError) -> Error {
        Error::OpenSSL(e)
    }
}
