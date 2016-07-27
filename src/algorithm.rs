use std;
use Error;
/// A trait that transmutes u8-sized slices into u8-sized slices.
pub unsafe trait FromSlice: Sized {
    fn from_slice(x: &[u8]) -> &[Self] {
        unsafe { std::slice::from_raw_parts(x.as_ptr() as *const Self, x.len()) }
    }
}

pub fn to_slice<T: FromSlice>(t: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(t.as_ptr() as *const u8, t.len()) }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum PublicKeyAlgorithm {
    RSAEncryptSign = 1,
    RSAEncrypt = 2,
    RSASign = 3,
    Elgamal = 16,
    DSA = 17,
    EllipticCurve = 18,
    ECDSA = 19,
    DiffieHellman = 21,
    // Not part of the RFC, but used by gnupg.
    Ed25519 = 22,
}
unsafe impl FromSlice for PublicKeyAlgorithm {}


impl PublicKeyAlgorithm {
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            1 => Ok(PublicKeyAlgorithm::RSAEncryptSign),
            2 => Ok(PublicKeyAlgorithm::RSAEncrypt),
            3 => Ok(PublicKeyAlgorithm::RSASign),
            16 => Ok(PublicKeyAlgorithm::Elgamal),
            17 => Ok(PublicKeyAlgorithm::DSA),
            18 => Ok(PublicKeyAlgorithm::EllipticCurve),
            19 => Ok(PublicKeyAlgorithm::ECDSA),
            21 => Ok(PublicKeyAlgorithm::DiffieHellman),
            //
            22 => Ok(PublicKeyAlgorithm::Ed25519),
            t => Err(Error::UnknownPublicKeyAlgorithm(t)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum SymmetricKeyAlgorithm {
    Plain = 0,
    IDEA = 1,
    TripleDES = 2,
    CAST5 = 3,
    Blowfish = 4,
    AES128 = 7,
    AES192 = 8,
    AES256 = 9,
    TwoFish256 = 10,
}
unsafe impl FromSlice for SymmetricKeyAlgorithm {}


impl SymmetricKeyAlgorithm {
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(SymmetricKeyAlgorithm::Plain),
            1 => Ok(SymmetricKeyAlgorithm::IDEA),
            2 => Ok(SymmetricKeyAlgorithm::TripleDES),
            3 => Ok(SymmetricKeyAlgorithm::CAST5),
            4 => Ok(SymmetricKeyAlgorithm::Blowfish),
            7 => Ok(SymmetricKeyAlgorithm::AES128),
            8 => Ok(SymmetricKeyAlgorithm::AES192),
            9 => Ok(SymmetricKeyAlgorithm::AES256),
            10 => Ok(SymmetricKeyAlgorithm::TwoFish256),
            t => Err(Error::UnknownSymmetricKeyAlgorithm(t)),
        }
    }
}


#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    Zip = 1,
    Zlib = 2,
    Bzip2 = 3,
}
unsafe impl FromSlice for CompressionAlgorithm {}
impl CompressionAlgorithm {
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0 => Ok(CompressionAlgorithm::Uncompressed),
            1 => Ok(CompressionAlgorithm::Zip),
            2 => Ok(CompressionAlgorithm::Zlib),
            3 => Ok(CompressionAlgorithm::Bzip2),
            t => Err(Error::UnknownCompressionAlgorithm(t)),
        }
    }
}


#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum HashAlgorithm {
    Md5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA256 = 8,
    SHA384 = 9,
    SHA512 = 10,
    SHA224 = 11,
}
unsafe impl FromSlice for HashAlgorithm {}

impl HashAlgorithm {
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            1 => Ok(HashAlgorithm::Md5),
            2 => Ok(HashAlgorithm::SHA1),
            3 => Ok(HashAlgorithm::RIPEMD160),
            8 => Ok(HashAlgorithm::SHA256),
            9 => Ok(HashAlgorithm::SHA384),
            10 => Ok(HashAlgorithm::SHA512),
            11 => Ok(HashAlgorithm::SHA224),
            t => Err(Error::UnknownHashAlgorithm(t)),
        }
    }
}
