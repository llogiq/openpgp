//! The goal of this crate is to interact with the OpenPGP-format,
//! i.e. parse it and produce correct PGP files.  OpenPGP can describe
//! so many things that parsing is much more pleasant to write in an
//! event-driven way, and the resulting API is also smaller.
//!
//! This version is not yet able to produce encrypted content, but
//! signed messages should work, as demonstrated by the following
//! example, which reads a private key (in the format output by `gpg
//! --export-secret-keys -a`), signs a message and reads it back,
//! verifying the signature.
//!
//! PGP files are split into *packets*, with different meanings.
//!
//! ```
//! use openpgp::*;
//! use openpgp::key::*;
//! struct P {
//!     key: Option<Key>,
//!     subkey: Option<Key>,
//!     data: Vec<u8>,
//!     password: &'static [u8],
//! }
//!
//! impl PGP for P {
//!
//!     fn get_secret_key<'a>(&'a mut self, _: &[u8]) -> &'a key::SecretKey {
//!         self.subkey.as_ref().unwrap().unwrap_secret()
//!     }
//!
//!     fn get_password(&mut self) -> &[u8] {
//!         &self.password
//!     }
//!
//!     fn public_key(&mut self, _: u32, public_key: key::PublicKey) -> Result<(), Error> {
//!         self.key = Some(Key::Public(public_key));
//!         Ok(())
//!     }
//!
//!     fn secret_key(&mut self, _: u32, secret_key: key::SecretKey) -> Result<(), Error> {
//!         self.key = Some(Key::Secret(secret_key));
//!         Ok(())
//!     }
//!     fn secret_subkey(&mut self, _: u32, secret_key: key::SecretKey) -> Result<(), Error> {
//!         self.subkey = Some(Key::Secret(secret_key));
//!         Ok(())
//!     }
//!     fn get_public_signing_key<'a>(&'a mut self, keyid: &[u8]) -> Option<&'a key::Key> {
//!         self.key.as_ref()
//!     }
//!     fn signature_verified(&mut self, is_ok:bool) -> Result<(), Error> {
//!         println!("Verified: {:?}", is_ok);
//!         Ok(())
//!     }
//!     fn get_signed_data(&mut self, _: signature::Type) -> &[u8] {
//!         &self.data
//!     }
//!
//! }
//! let secret_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n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\n=USRz\n-----END PGP PRIVATE KEY BLOCK-----\n";
//!
//! let contents = b"Moi non plus, Bob";
//! let mut p = P {
//!     key: None,
//!     subkey: None,
//!     data: contents.to_vec(),
//!     password: b"blabla blibli",
//! };
//!
//! {
//!     let mut sk = secret_key.as_bytes();
//!     let sk = read_armored(&mut sk);
//!     let mut sk = &sk[..];
//!     parse(&mut p, &mut sk).unwrap();
//! };
//!
//! let mut s = Vec::new();
//! {
//!     let mut buf = Vec::new();
//!
//!     let now = std::time::SystemTime::now();
//!     let now = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
//!     if let Some(Key::Secret(ref sk)) = p.key {
//!         sk.sign(&mut buf,
//!                 contents,
//!                 signature::Type::Binary,
//!                 &[signature::Subpacket::SignatureCreationTime(now)],
//!                 &[])
//!           .unwrap();
//!         packet::write(&mut s, packet::Tag::Signature, &buf).unwrap();
//!     }
//! }
//! let mut slice = &s[..];
//! parse(&mut p, &mut slice).unwrap();
//! ```

#[macro_use]
extern crate log;
extern crate byteorder;
extern crate rustc_serialize;
extern crate libc;
#[macro_use]
extern crate bitflags;
extern crate openssl;
extern crate flate2;


use rustc_serialize::base64::FromBase64;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Read, Write, BufRead};

#[cfg(test)]
extern crate rand;
mod error;
pub use error::Error;

mod algorithm;
use algorithm::*;
mod encoding;
use encoding::*;
mod sodium;
pub mod packet;

pub mod signature;

pub mod key;


#[derive(Debug)]
enum SymmetricKey {
    AES256([u8; 32]),
}

const PK_SESSION_KEY_VERSION: u8 = 3;
const SYM_INT_DATA_VERSION: u8 = 1;
const ONE_PASS_VERSION: u8 = 3;

struct Parser {
    mdc_hash: Option<Vec<u8>>,
    one_pass: Vec<OnePass>,
    session_key: Option<SymmetricKey>
}

#[allow(dead_code)]
struct OnePass {
    sig_type: signature::Type,
    hasher: openssl::crypto::hash::Hasher,
    pk_algo: PublicKeyAlgorithm,
    keyid: [u8; 8],
}

/// This trait is mostly a collection of callbacks called while parsing a series of PGP packets.
pub trait PGP: Sized {

    /// Called when the given public key is about to be used for
    /// verifying a signature. The default implementation just panics.
    #[allow(unused_variables)]
    fn get_public_signing_key<'a>(&'a mut self, keyid: &[u8]) -> Option<&'a key::Key> {
        unimplemented!()
    }

    /// Called when the secret key with the given identifier is
    /// needed. The default implementation just panics.
    #[allow(unused_variables)]
    fn get_secret_key<'a>(&'a mut self, keyid: &[u8]) -> &'a key::SecretKey {
        unimplemented!()
    }

    /// Called when a password is required to decrypt a secret/private key.
    #[allow(unused_variables)]
    fn get_password(&mut self) -> &[u8] {
        unimplemented!()
    }

    /// Should return the data signed by a signature packet.
    #[allow(unused_variables)]
    fn get_signed_data(&mut self, sigtype: signature::Type) -> &[u8] {
        unimplemented!()
    }

    /// Called on a public key packet.
    #[allow(unused_variables)]
    fn public_key(&mut self, creation_time: u32, pk: key::PublicKey) -> Result<(), Error> {
        debug!("public key: {:?}", creation_time);
        Ok(())
    }

    /// Called on a public subkey packet.
    #[allow(unused_variables)]
    fn public_subkey(&mut self, creation_time: u32, pk: key::PublicKey) -> Result<(), Error> {
        debug!("public subkey: {:?}", creation_time);
        Ok(())
    }

    /// Called on a secret key packet.
    #[allow(unused_variables)]
    fn secret_key(&mut self, creation_time: u32, pk: key::SecretKey) -> Result<(), Error> {
        debug!("secret key: {:?}", creation_time);
        Ok(())
    }

    /// Called on a secret subkey packet.
    #[allow(unused_variables)]
    fn secret_subkey(&mut self, creation_time: u32, pk: key::SecretKey) -> Result<(), Error> {
        debug!("secret subkey: {:?}", creation_time);
        Ok(())
    }

    /// Called on a userid packet, this is normally used to store a user's name and email address.
    #[allow(unused_variables)]
    fn user_id(&mut self, user_id: &str) -> Result<(), Error> {
        debug!("user id: {:?}", user_id);
        Ok(())
    }

    /// Called on a user attribute packet, which is used to store
    /// free-form extra information about the user. The only
    /// `attribute_type` defined in RFC4880 is `1`, which means it's
    /// an image (of unspecified format, good luck!).
    #[allow(unused_variables)]
    fn user_attribute(&mut self, attribute_type: u8, attr: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    /// Signatures can be used on a wide variety of things, and their
    /// meaning is specified by one or more subpackets.
    #[allow(unused_variables)]
    fn signature_subpacket(&mut self, subpacket: signature::Subpacket) -> Result<(), Error> {
        debug!("subpacket: {:?}", subpacket);
        Ok(())
    }

    /// Called when we've read a signature packet and checked the
    /// signature. This function is always called after verifying a
    /// signature, no matter whether the signature is valid (this is
    /// specified by `is_ok`).
    #[allow(unused_variables)]
    fn signature_verified(&mut self, is_ok:bool) -> Result<(), Error> {
        debug!("signature is ok: {:?}", is_ok);
        Ok(())
    }

    /// "Raw" data packet.
    #[allow(unused_variables)]
    fn literal(&mut self, file_name:&str, date:u32, literal: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    /// Trust packet, mostly free/unspecified -form. I wouldn't rely too much on what's in there.
    #[allow(unused_variables)]
    fn trust(&mut self, trust: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

/// Start the parsing. The default implementation should probably not be overwritten.
pub fn parse<P:PGP, R: Read>(p: &mut P, r: &mut R) -> Result<(), Error> {
    let mut parser = Parser {
        mdc_hash: None,
        one_pass: Vec::new(),
        session_key: None
    };
    let mut buffer = Vec::new();
    parse_(p, r, &mut buffer, &mut parser)
}


fn parse_<R: Read, P: PGP>(p: &mut P,
                           r: &mut R,
                           packet_body: &mut Vec<u8>,
                           parser: &mut Parser)
                           -> Result<(), Error> {

    loop {
        match packet::read(r, packet_body) {
            Ok(packet::Tag::PublicKeyEncryptedSessionKey) => {
                parser.session_key = Some(try!(parse_pk_session_key(p, &packet_body)));
            }

            Ok(packet::Tag::Signature) => {
                parser.one_pass.pop(); // This is not actually used by GnuPG.
                try!(signature::read(p, &packet_body));
            }

            Ok(packet::Tag::SymmetricKeyEncryptedSessionKey) => unimplemented!(),

            Ok(packet::Tag::OnePassSignature) => {

                // This is not actually used by GnuPG.
                let mut body = &packet_body[..];
                let version = try!(body.read_u8());
                assert_eq!(version, ONE_PASS_VERSION);
                let sig_type = try!(signature::Type::from_byte(try!(body.read_u8())));
                let hash_algo = try!(HashAlgorithm::from_byte(try!(body.read_u8())));
                let pk_algo = try!(PublicKeyAlgorithm::from_byte(try!(body.read_u8())));

                let (keyid, mut body) = body.split_at(8);

                let _ = try!(body.read_u8()) == 0; // is it nested?

                let mut kid = [0; 8];
                (&mut kid).clone_from_slice(keyid);
                use openssl::crypto::hash::*;
                let hash_type = match hash_algo {
                    HashAlgorithm::SHA1 => Type::SHA1,
                    HashAlgorithm::SHA256 => Type::SHA256,
                    _ => unimplemented!(),
                };
                parser.one_pass.push(OnePass {
                    sig_type: sig_type,
                    hasher: Hasher::new(hash_type),
                    pk_algo: pk_algo,
                    keyid: kid,
                });
            }

            Ok(packet::Tag::SecretKey) => {
                let mut slice = &packet_body[..];
                let (creation_time, sk) = try!(key::SecretKey::read(&mut slice, p.get_password()));
                try!(p.secret_key(creation_time, sk))
            }

            Ok(packet::Tag::PublicKey) => {
                let mut slice = &packet_body[..];
                let (creation_time, pk) = try!(key::PublicKey::read(&mut slice));
                try!(p.public_key(creation_time, pk))
            }

            Ok(packet::Tag::SecretSubkey) => {
                let mut slice = &packet_body[..];
                let (creation_time, sk) = try!(key::SecretKey::read(&mut slice, p.get_password()));
                try!(p.secret_subkey(creation_time, sk))
            }

            Ok(packet::Tag::CompressedData) => {
                let mut body = &packet_body[..];
                let comp_algo = try!(CompressionAlgorithm::from_byte(try!(body.read_u8())));
                match comp_algo {
                    CompressionAlgorithm::Uncompressed => try!(parse(p, &mut body)),
                    CompressionAlgorithm::Zip => {
                        let mut decoder = flate2::read::DeflateDecoder::new(&mut body);
                        let mut buf = Vec::new();
                        try!(decoder.read_to_end(&mut buf));
                        let mut slice = &buf[..];
                        try!(parse(p, &mut slice))
                    }
                    CompressionAlgorithm::Zlib => {
                        let mut decoder = flate2::read::ZlibDecoder::new(&mut body);
                        let mut buf = Vec::new();
                        try!(decoder.read_to_end(&mut buf));
                        let mut slice = &buf[..];
                        try!(parse(p, &mut slice))
                    }
                    CompressionAlgorithm::Bzip2 => unimplemented!(),
                }
            }

            Ok(packet::Tag::SymmetricallyEncryptedData) => unimplemented!(),

            Ok(packet::Tag::Marker) => {
                // This is obsolete in RFC4880
                unimplemented!()
            }

            Ok(packet::Tag::LiteralData) => {

                let mut lit = &packet_body[..];


                let type_ = try!(lit.read_u8());
                let file_name = {
                    let len = try!(lit.read_u8()) as usize;
                    let (a, b) = lit.split_at(len);
                    lit = b;
                    a
                };
                let date = try!(lit.read_u32::<BigEndian>());

                match type_ {
                    b'b' => {
                        for onepass in &mut parser.one_pass {
                            try!(onepass.hasher.write_all(lit));
                        }
                        try!(p.literal(try!(std::str::from_utf8(file_name)), date, lit));
                    }
                    _ => unimplemented!(),
                }
            }

            Ok(packet::Tag::Trust) => try!(p.trust(&packet_body)),

            Ok(packet::Tag::UserID) => try!(p.user_id(try!(std::str::from_utf8(&packet_body)))),

            Ok(packet::Tag::PublicSubkey) => {
                let mut slice = &packet_body[..];
                let (creation_time, pk) = try!(key::PublicKey::read(&mut slice));
                try!(p.public_subkey(creation_time, pk))
            }

            Ok(packet::Tag::UserAttribute) => {
                let mut slice = &packet_body[..];
                while !slice.is_empty() {
                    let p0 = try!(slice.read_u8()) as usize;
                    let len = try!(read_length(p0, &mut slice));
                    let (mut a, b) = slice.split_at(len);
                    slice = b;
                    let typ = try!(a.read_u8());
                    try!(p.user_attribute(typ, a))
                }

            }

            Ok(packet::Tag::SymIntData) => {
                let mut body = &packet_body[..];
                assert_eq!(try!(body.read_u8()), SYM_INT_DATA_VERSION);
                // decrypt(t: Type, key: &[u8], iv: &[u8], data: &[u8])
                const AES_BLOCK_SIZE: usize = 16;
                let data = match parser.session_key {
                    Some(SymmetricKey::AES256(ref k)) => {
                        // block size 16;
                        use openssl::crypto::symm::*;
                        let iv = [0; AES_BLOCK_SIZE];
                        decrypt(Type::AES_256_CFB128, k, &iv, body)
                    },
                    None => return Err(Error::NoSessionKey)
                };
                let (a, mut clear) = data.split_at(AES_BLOCK_SIZE + 2);
                let (_, a0) = a.split_at(AES_BLOCK_SIZE - 2);
                let (a0, a1) = a0.split_at(2);
                assert_eq!(a0, a1);
                let (clear0, mdc) = clear.split_at(clear.len() - 22);
                if mdc[0] == 0xD3 && mdc[1] == 0x14 {
                    // This packet is not produced by GnuPG, contrarily to RFC4880.
                    use openssl::crypto::hash::{hash, Type};
                    parser.mdc_hash = Some(hash(Type::SHA1, clear0));
                }
                let mut new_body = Vec::new();
                try!(parse_(p, &mut clear, &mut new_body, parser))
            }

            Ok(packet::Tag::ModificationDetectionCode) => {
                // Already handled before.
                if let Some(ref h) = parser.mdc_hash {
                    assert_eq!(&packet_body[..], &h[..])
                }
            }
            Err(e) => {
                debug!("error {:?}", e);
                break;
            }
        }
    }
    Ok(())
}



fn parse_pk_session_key<P: PGP>(p: &mut P, mut body: &[u8]) -> Result<SymmetricKey, Error> {

    let version = try!(body.read_u8());

    assert_eq!(version, PK_SESSION_KEY_VERSION);

    let (keyid, b) = body.split_at(8);
    body = b;

    let algo = try!(PublicKeyAlgorithm::from_byte(try!(body.read_u8())));
    match algo {
        PublicKeyAlgorithm::RSAEncryptSign => {
            match *p.get_secret_key(keyid) {

                key::SecretKey::RSAEncryptSign(ref pk) => {

                    use openssl::crypto::pkey::*;
                    let mut key = PKey::new();
                    key.set_rsa(pk);
                    let mpi = try!(body.read_mpi());

                    let session_key = key.private_decrypt_with_padding(mpi,
                                                                       EncryptionPadding::PKCS1v15);
                    let mut session_key = &session_key[..];
                    debug!("session key {:?}", session_key);
                    let algo = try!(session_key.read_u8());
                    debug!("algo {:?}", algo);
                    let (key, mut check) = session_key.split_at(session_key.len() - 2);

                    match try!(SymmetricKeyAlgorithm::from_byte(algo)) {

                        SymmetricKeyAlgorithm::AES256 => {

                            let mut k = [0; 32];
                            k.clone_from_slice(key);
                            use std::num::Wrapping;
                            let mut checksum: Wrapping<u16> = Wrapping(0);
                            for &byte in key {
                                checksum += Wrapping(byte as u16)
                            }
                            assert_eq!(checksum.0, check.read_u16::<BigEndian>().unwrap());
                            Ok(SymmetricKey::AES256(k))
                        }
                        _ => unimplemented!(),
                    }
                }
                _ => unimplemented!(),
            }
        }
        _ => unimplemented!(),
    }
}



pub fn read_armored<R: BufRead>(r: &mut R) -> Vec<u8> {
    let mut buf = String::new();
    let mut fin = String::new();
    let mut armor_started = false;
    let mut contents_started = false;

    loop {
        buf.clear();
        let n = r.read_line(&mut buf).unwrap();
        if n == 0 {
            break;
        }

        let tr = buf.trim_right();
        if tr.starts_with("-----BEGIN PGP ") && tr.ends_with("-----") {
            armor_started = true
        } else if tr.starts_with("-----END PGP ") && tr.ends_with("-----") {
            break;
        } else if armor_started {
            if contents_started {
                if buf.starts_with('=') {
                    contents_started = false
                } else {
                    fin = fin + buf.trim_right()
                }
            } else if buf.trim_right() == "" {
                contents_started = true
            }
        }
    }
    fin.from_base64().unwrap()
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;
    use std;
    use key::*;
    const SECRET_KEY: &'static str = include_str!("secret_key.asc");
    const PUBLIC_KEY:&'static str = include_str!("public_key.asc");


    struct P {
        key: Option<Key>,
        subkey: Option<Key>,
        data: Vec<u8>,
        password: &'static [u8],
    }

    impl PGP for P {
        fn get_secret_key<'a>(&'a mut self, _: &[u8]) -> &'a key::SecretKey {
            if let Some(Key::Secret(ref key)) = self.subkey {
                key
            } else {
                panic!("no key")
            }
        }
        fn get_signed_data(&mut self, sigtype: signature::Type) -> &[u8] {
            &self.data
        }
        fn get_public_signing_key<'a>(&'a mut self, keyid: &[u8]) -> Option<&'a key::Key> {
            self.key.as_ref()
        }
        fn get_password(&mut self) -> &[u8] {
            &self.password
        }

        fn public_key(&mut self, _: u32, public_key: key::PublicKey) -> Result<(), Error> {
            self.key = Some(Key::Public(public_key));
            Ok(())
        }
        fn secret_key(&mut self, _: u32, secret_key: key::SecretKey) -> Result<(), Error> {
            self.key = Some(Key::Secret(secret_key));
            Ok(())
        }
        fn secret_subkey(&mut self, _: u32, secret_key: key::SecretKey) -> Result<(), Error> {
            self.subkey = Some(Key::Secret(secret_key));
            Ok(())
        }

        fn literal(&mut self, file_name:&str, date:u32, literal: &[u8]) -> Result<(), Error> {
            println!("literal: {:?} {:?}", file_name, date);
            self.data.clear();
            self.data.extend(literal);
            Ok(())
        }

        fn signature_verified(&mut self, is_ok:bool) -> Result<(), Error> {
            println!("Verified: {:?}", is_ok);
            Ok(())
        }
    }



    #[test]
    fn verify() {
        let _ = env_logger::init();
        let contents = b"Test";
        let signature = include_str!("signature.asc");


        let base = {
            let mut pubkey = PUBLIC_KEY.as_bytes();
            super::read_armored(&mut pubkey)
        };
        let mut slice = &base[..];
        let mut p = P {
            key: None,
            subkey: None,
            data: contents.to_vec(),
            password: b"",
        };
        parse(&mut p, &mut slice).unwrap();
        let s = {
            let mut signature = signature.as_bytes();
            super::read_armored(&mut signature)
        };
        let mut slice = &s[..];
        parse(&mut p, &mut slice).unwrap();
    }

    #[test]
    fn sign_verify() {

        let _ = env_logger::init();

        let contents = b"This is a test file";

        let mut p = P {
            key: None,
            subkey: None,
            data: contents.to_vec(),
            password: b"blabla blibli",
        };

        {
            // reading secret key.
            let mut sk = SECRET_KEY.as_bytes();
            let sk = super::read_armored(&mut sk);
            let mut sk = &sk[..];
            parse(&mut p, &mut sk).unwrap();
        };
        let mut s = Vec::new();
        {
            let mut buf = Vec::new();

            let now = std::time::SystemTime::now();
            let now = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
            if let Some(Key::Secret(ref sk)) = p.key {
                sk.sign(&mut buf,
                        contents,
                        signature::Type::Binary,
                        &[signature::Subpacket::SignatureCreationTime(now)],
                        &[])
                  .unwrap();
                packet::write(&mut s, packet::Tag::Signature, &buf).unwrap();
            }
        }
        let mut slice = &s[..];
        parse(&mut p, &mut slice).unwrap();

    }

    #[test]
    fn keyring_open() {

        let _ = env_logger::init();
        let mut p = P {
            key: None,
            subkey: None,
            data: b"".to_vec(),
            password: b"blabla blibli",
        };

        {
            // reading secret key.
            let mut sk = SECRET_KEY.as_bytes();
            let sk = super::read_armored(&mut sk);
            let mut sk = &sk[..];
            parse(&mut p, &mut sk).unwrap();
        }
        assert!(p.key.is_some())
    }

    #[test]
    fn keyring_open_save() {


        let _ = env_logger::init();
        let mut p = P {
            key: None,
            subkey: None,
            data: b"".to_vec(),
            password: b"blabla blibli",
        };

        {
            // reading secret key.
            let mut sk = SECRET_KEY.as_bytes();
            let sk = super::read_armored(&mut sk);
            let mut sk = &sk[..];
            parse(&mut p, &mut sk).unwrap();
        }

        if let Some(Key::Secret(ref sk)) = p.key {

            let mut v = Vec::new();
            let new_password = b"new_password";
            let now = std::time::SystemTime::now();
            let now = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;

            sk.write(&mut v,
                     now,
                     super::algorithm::SymmetricKeyAlgorithm::AES128,
                     new_password)
              .unwrap();
            let mut v = &v[..];
            key::SecretKey::read(&mut v, new_password).unwrap();
        }
    }


    #[test]
    fn email_pgp_message() {
        let email = include_str!("email.asc");

        let email = {
            let mut email = email.as_bytes();
            super::read_armored(&mut email)
        };
        let mut email = &email[..];

        let mut p = P {
            key: None,
            subkey: None,
            data: b"".to_vec(),
            password: b"blabla blibli",
        };

        {
            // reading secret key.
            let mut sk = SECRET_KEY.as_bytes();
            let sk = super::read_armored(&mut sk);
            let mut sk = &sk[..];
            parse(&mut p, &mut sk).unwrap();
        }

        parse(&mut p, &mut email).unwrap();
    }

    // This fails, because it's a DSA key, which is not included in OpenSSL.
    // #[test]
    // fn rustup_pgp_key() {
    // let key = "-----BEGIN PGP PUBLIC KEY BLOCK-----
    // Version: GnuPG v1
    //
    // mQGiBFSvfs0RBACq3IMYK0JuSu764zrWfAh4hu1wnb8XMlXxj23drkGqSMHAW1fj
    // VoA4etCwhumoqyhYtRkr4Rnae+le2FcYy8MUpSE+zQbX5X37saO0ppDXbKh0PLzw
    // /0qQ6YhKllJX9T/cSH4LSw0JGFyHs5Nj+4sVsGexhn8mkuqkM6wBk6RGTwCgiYJB
    // nWtKygKH1koIsSIQ5mxhQWMD/imRz4zH/tUDMF7PepRehOtbIIYI+B7m80Xz5gfU
    // HwMiXRgWBRClbPbUDzEwb6sEfBn104tRgHtHetBFRV9niAuwqycJSd1b/Em4PanZ
    // TO8dZzglD0VxKJDnlxKWb4YAs6082p6zWgCf4EK2EI6jc6KExy3rY7SJgWBibxPb
    // nLBBA/9xKWCs7OxOtDdojh2nI7ZH0O5x+ycPohrLZ2S9pd9kg4QgaeXqDyKbp00h
    // slIz768WgAPwluE+sLq2H9967kjKII2D3giiKp/HvV6ew7mZpNOARYxZVJW948kw
    // Tj4H+WCycbRwp6dj52fD+r+TrJnWF/wcdj1s9hNKeohi8peQY7QSbXVsdGlydXN0
    // IHRlc3Qga2V5iGIEExECACIFAlSvfs0CGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B
    // AheAAAoJENsvtiW3Dh9iKtcAnAkhTbaaid6u9a1ctSIr0s0FsxDaAJ4y8IBNvFAj
    // BZVWgYLtCDPB3nYkeA==
    // =zJHN
    // -----END PGP PUBLIC KEY BLOCK-----
    // ";
    //
    // let base = {
    // let mut pubkey = key.as_bytes();
    // super::read_armored(&mut pubkey)
    // };
    // let mut slice = &base[..];
    // let pubkey = {
    // read_pubkey(&mut slice).unwrap()
    // };
    // }
    //

}
