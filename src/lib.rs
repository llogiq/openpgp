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
use byteorder::{BigEndian, ReadBytesExt, ByteOrder};
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
mod packet;

pub mod signature;
mod key;


#[derive(Debug)]
pub enum SymmetricKey {
    AES256([u8; 32]),
}

const PK_SESSION_KEY_VERSION: u8 = 3;
const SYM_INT_DATA_VERSION: u8 = 1;
const ONE_PASS_VERSION: u8 = 3;

struct Parse {
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

pub trait PGP: Sized {
    #[allow(unused_variables)]
    fn get_secret_key<'a>(&'a mut self, keyid: &[u8]) -> &'a key::SecretKey {
        unimplemented!()
    }

    #[allow(unused_variables)]
    fn get_password(&mut self) -> &[u8] {
        unimplemented!()
    }

    #[allow(unused_variables)]
    fn public_key(&mut self, creation_time: u32, pk: key::PublicKey) -> Result<(), Error> {
        println!("public key: {:?}", creation_time);
        Ok(())
    }
    #[allow(unused_variables)]
    fn public_subkey(&mut self, creation_time: u32, pk: key::PublicKey) -> Result<(), Error> {
        println!("public subkey: {:?}", creation_time);
        Ok(())
    }

    #[allow(unused_variables)]
    fn secret_key(&mut self, creation_time: u32, pk: key::SecretKey) -> Result<(), Error> {
        println!("secret key: {:?}", creation_time);
        Ok(())
    }

    #[allow(unused_variables)]
    fn secret_subkey(&mut self, creation_time: u32, pk: key::SecretKey) -> Result<(), Error> {
        println!("secret subkey: {:?}", creation_time);
        Ok(())
    }

    #[allow(unused_variables)]
    fn user_id(&mut self, user_id: &str) -> Result<(), Error> {
        println!("user id: {:?}", user_id);
        Ok(())
    }

    #[allow(unused_variables)]
    fn user_attribute(&mut self, typ: u8, attr: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn signature(&mut self, packet: signature::SignaturePacket) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn literal(&mut self, literal: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    #[allow(unused_variables)]
    fn trust(&mut self, trust: &[u8]) -> Result<(), Error> {
        Ok(())
    }

    fn parse<R: Read>(&mut self, r: &mut R) -> Result<(), Error> {
        let mut parse = Parse {
            mdc_hash: None,
            one_pass: Vec::new(),
            session_key: None
        };
        let mut buffer = Vec::new();
        parse_(self, r, &mut buffer, &mut parse)
    }
}



fn parse_<R: Read, P: PGP>(p: &mut P,
                           r: &mut R,
                           packet_body: &mut Vec<u8>,
                           parse: &mut Parse)
                           -> Result<(), Error> {

    loop {
        match packet::read(r, packet_body) {
            Ok(packet::Tag::PublicKeyEncryptedSessionKey) => {
                parse.session_key = Some(try!(parse_pk_session_key(p, &packet_body)));
            }

            Ok(packet::Tag::Signature) => {
                parse.one_pass.pop(); // This is not actually used by GnuPG.
                let packet = signature::SignaturePacket(&packet_body);
                try!(p.signature(packet))
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
                parse.one_pass.push(OnePass {
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
                    CompressionAlgorithm::Uncompressed => try!(p.parse(&mut body)),
                    CompressionAlgorithm::Zip => {
                        let mut decoder = flate2::read::DeflateDecoder::new(&mut body);
                        let mut buf = Vec::new();
                        try!(decoder.read_to_end(&mut buf));
                        let mut slice = &buf[..];
                        try!(p.parse(&mut slice))
                    }
                    CompressionAlgorithm::Zlib => {
                        let mut decoder = flate2::read::ZlibDecoder::new(&mut body);
                        let mut buf = Vec::new();
                        try!(decoder.read_to_end(&mut buf));
                        let mut slice = &buf[..];
                        try!(p.parse(&mut slice))
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
                println!("name {:?} date {:?}", std::str::from_utf8(file_name), date);

                match type_ {
                    b'b' => {
                        println!("{:?}", String::from_utf8_lossy(lit));
                        for onepass in parse.one_pass.iter_mut() {
                            try!(onepass.hasher.write_all(lit));
                        }
                        try!(p.literal(lit));
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
                let data = match parse.session_key {
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
                    parse.mdc_hash = Some(hash(Type::SHA1, clear0));
                }
                let mut new_body = Vec::new();
                try!(parse_(p, &mut clear, &mut new_body, parse))
            }

            Ok(packet::Tag::ModificationDetectionCode) => {
                // Already handled before.
                if let Some(ref h) = parse.mdc_hash {
                    assert_eq!(&packet_body[..], &h[..])
                }
            }
            Err(e) => {
                println!("error {:?}", e);
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
            match p.get_secret_key(keyid) {

                &key::SecretKey::RSAEncryptSign(ref pk) => {

                    use openssl::crypto::pkey::*;
                    let mut key = PKey::new();
                    key.set_rsa(pk);
                    let mpi = try!(body.read_mpi());
                    println!("mpi {:?}", mpi);

                    let session_key = key.private_decrypt_with_padding(mpi,
                                                                       EncryptionPadding::PKCS1v15);
                    let mut session_key = &session_key[..];
                    println!("session key {:?}", session_key);
                    let algo = try!(session_key.read_u8());
                    println!("algo {:?}", algo);
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
                if buf.starts_with("=") {
                    contents_started = false
                } else {
                    fin = fin + buf.trim_right()
                }
            } else {
                if buf.trim_right() == "" {
                    contents_started = true
                }
            }
        }
    }
    fin.from_base64().unwrap()
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;
    use super::packet;
    use super::key;
    use std;
    use signature::Verify;

    const SECRET_KEY: &'static str = include_str!("secret_key.asc");
    const PUBLIC_KEY:&'static str = include_str!("public_key.asc");

    enum Key {
        Public(key::PublicKey),
        Secret(key::SecretKey),
    }

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

        fn get_password(&mut self) -> &[u8] {
            &self.password
        }

        fn public_key(&mut self, _: u32, public_key: key::PublicKey) -> Result<(), Error> {
            println!("PK ============================== ");
            self.key = Some(Key::Public(public_key));
            Ok(())
        }
        fn secret_key(&mut self, _: u32, secret_key: key::SecretKey) -> Result<(), Error> {
            println!("SK ============================== ");
            self.key = Some(Key::Secret(secret_key));
            Ok(())
        }
        fn secret_subkey(&mut self, _: u32, secret_key: key::SecretKey) -> Result<(), Error> {
            println!("SK ============================== ");
            self.subkey = Some(Key::Secret(secret_key));
            Ok(())
        }

        fn literal(&mut self, literal: &[u8]) -> Result<(), Error> {
            println!("LITERAL ===========");
            self.data.clear();
            self.data.extend(literal);
            Ok(())
        }

        fn signature(&mut self, packet: signature::SignaturePacket) -> Result<(), Error> {

            println!("SIGNATURE ============================== ");
            if let Some(ref pk) = self.key {
                let verif = match *pk {
                    Key::Public(ref k) => k.verify(packet, &self.data),
                    Key::Secret(ref k) => k.verify(packet, &self.data),
                };
                println!("VERIFY?: {:?}", verif);

            }
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
        p.parse(&mut slice).unwrap();
        let s = {
            let mut signature = signature.as_bytes();
            super::read_armored(&mut signature)
        };
        let mut slice = &s[..];
        p.parse(&mut slice).unwrap();
    }

    #[test]
    fn sign_verify() {

        let _ = env_logger::init();

        let contents = b"This is a test file";
        println!("reading secret key");

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
            p.parse(&mut sk).unwrap();
        };
        println!("Done reading keys");
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
                println!("buf: {:?}", buf);
                packet::write_packet(&mut s, packet::Tag::Signature, &buf).unwrap();
            }
        }
        let mut slice = &s[..];
        p.parse(&mut slice).unwrap();

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
            p.parse(&mut sk).unwrap();
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
            p.parse(&mut sk).unwrap();
        }

        if let Some(Key::Secret(ref sk)) = p.key {

            println!("key read");
            let mut v = Vec::new();
            let new_password = b"new_password";
            let now = std::time::SystemTime::now();
            let now = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;

            sk.write(&mut v,
                     now,
                     super::algorithm::SymmetricKeyAlgorithm::AES128,
                     new_password)
              .unwrap();
            println!("key written");
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
            p.parse(&mut sk).unwrap();
        }

        println!("==================== parsing email");
        p.parse(&mut email).unwrap();
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
