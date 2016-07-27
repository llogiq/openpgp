use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt, ByteOrder};

use {sodium, Error};

use rustc_serialize::hex::ToHex;
use std;
use std::io::{Write};
use openssl::crypto::hash;
use key::{PublicKey, SecretKey, Key};
use algorithm::*;
use encoding::{ReadValue, WriteValue, read_length};

// https://tools.ietf.org/html/rfc4880#section-5.2.1
// sed -e "s/ *\(.*\) = \(.*\),/\2 => Some(Type::\1),/"
#[derive(Debug)]
pub enum Type {
    Binary = 0x00,
    CanonicalText = 0x01,
    Standalone = 0x02,
    GenericCert = 0x10,
    PersonaCert = 0x11,
    CasualCert = 0x12,
    PositiveCert = 0x13,
    SubkeyBinding = 0x18,
    PrimaryKeyBinding = 0x19,
    DirectlyOnAKey = 0x1F,
    KeyRevocation = 0x20,
    SubkeyRevocation = 0x28,
    CertificationRevocation = 0x30,
    Timestamp = 0x40,
    ThirdPartyConfirmation = 0x50,
}
impl Type {
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x00 => Ok(Type::Binary),
            0x01 => Ok(Type::CanonicalText),
            0x02 => Ok(Type::Standalone),
            0x10 => Ok(Type::GenericCert),
            0x11 => Ok(Type::PersonaCert),
            0x12 => Ok(Type::CasualCert),
            0x13 => Ok(Type::PositiveCert),
            0x18 => Ok(Type::SubkeyBinding),
            0x19 => Ok(Type::PrimaryKeyBinding),
            0x1F => Ok(Type::DirectlyOnAKey),
            0x20 => Ok(Type::KeyRevocation),
            0x28 => Ok(Type::SubkeyRevocation),
            0x30 => Ok(Type::CertificationRevocation),
            0x40 => Ok(Type::Timestamp),
            0x50 => Ok(Type::ThirdPartyConfirmation),
            t => Err(Error::UnknownSignatureType(t)),
        }
    }
}

fn sha256_version4(data: &[u8], hashed_sig_data: &[u8]) -> sodium::sha256::Digest {
    let mut v: Vec<u8> = Vec::new();
    v.extend(data);
    v.extend(hashed_sig_data);
    // https://tools.ietf.org/html/rfc4880#section-5.2.4
    v.push(4);
    v.push(0xff);
    v.write_u32::<BigEndian>(hashed_sig_data.len() as u32).unwrap();
    debug!("hashed value: {:?}", v);
    sodium::sha256::hash(&v)
}

impl Verify for PublicKey {
        
    fn verify_signature(&self, hash_algorithm:HashAlgorithm, hash:&[u8], signature:&[u8]) -> Result<bool, Error> {
        use key::PublicKey::*;
        match *self {
            Ed25519(ref pk) => {
                Ok(sodium::ed25519::verify_detached(&signature, hash, sodium::ed25519::PublicKey(pk)))
            },
            RSAEncryptSign(ref pk) => {
                let t = match hash_algorithm {
                    HashAlgorithm::SHA256 => hash::Type::SHA256,
                    _ => unimplemented!()
                };
                Ok(try!(pk.verify(t, hash, &signature)))
            }
        }
    }
}

impl Verify for SecretKey {
        
    fn verify_signature(&self, hash_algorithm:HashAlgorithm, hash:&[u8], signature:&[u8]) -> Result<bool, Error> {
        use key::SecretKey::*;
        match *self {
            Ed25519 { ref pk, .. } => {
                Ok(sodium::ed25519::verify_detached(&signature, hash, sodium::ed25519::PublicKey(pk)))
            },
            RSAEncryptSign(ref sk) => {
                let t = match hash_algorithm {
                    HashAlgorithm::SHA256 => hash::Type::SHA256,
                    _ => unimplemented!()
                };
                Ok(try!(sk.verify(t, hash, &signature)))
            }
        }
    }
}

impl Verify for Key {
    fn verify_signature(&self, hash_algorithm:HashAlgorithm, hash:&[u8], signature:&[u8]) -> Result<bool, Error> {
        match *self {
            Key::Secret(ref k) => k.verify_signature(hash_algorithm, hash, signature),
            Key::Public(ref k) => k.verify_signature(hash_algorithm, hash, signature)
        }
    }
}
#[derive(Copy, Clone)]
pub struct SignaturePacket<'a>(pub &'a [u8]);

pub trait Verify {

    fn verify_signature(&self, hash_algorithm:HashAlgorithm, hash:&[u8], sig:&[u8]) -> Result<bool, Error>;
    
    fn verify<B:AsRef<[u8]>>(&self,
                             body: SignaturePacket,
                             data: B)
                             -> Result<bool, Error> {
        let mut body = body.0;
        let data = data.as_ref();
        let initial_body = body;
        debug!("initial_body.len(): {:?}", initial_body.len());

        let version = try!(body.read_u8());

        debug!("signature version: {:?}", version);
        let (hash_algo, digest) = if version == 3 {

            if try!(body.read_u8()) != 5 {
                return Err(Error::InvalidSignature)
            }
            let initial_body = body;
            let sigtype = Type::from_byte(try!(body.read_u8()));
            let creation_time = try!(body.read_u32::<BigEndian>());
            let (key_id, mut body) = body.split_at(8);

            let pk_algo = try!(PublicKeyAlgorithm::from_byte(try!(body.read_u8())));
            let hash_algo = try!(HashAlgorithm::from_byte(try!(body.read_u8())));

            match pk_algo {
                PublicKeyAlgorithm::Ed25519 => {},
                PublicKeyAlgorithm::RSAEncryptSign => {},
                t => return Err(Error::UnsupportedPublicKey(t))
            }
            match hash_algo {
                HashAlgorithm::SHA256 => {},
                t => return Err(Error::UnsupportedHash(t))
            }
            
            let left_0 = try!(body.read_u8());
            let left_1 = try!(body.read_u8());


            let mut v: Vec<u8> = Vec::new();
            v.extend(data);
            v.extend(&initial_body[0..5]);
            let digest = sodium::sha256::hash(&v);

            if digest[0] != left_0 || digest[1] != left_1 {
                return Ok(false);
            }
            (hash_algo, digest)

        } else if version == 4 {

            let sigtype = Type::from_byte(try!(body.read_u8())).unwrap();
            let pk_algo = try!(PublicKeyAlgorithm::from_byte(try!(body.read_u8())));
            let hash_algo = try!(HashAlgorithm::from_byte(try!(body.read_u8())));
            match pk_algo {
                PublicKeyAlgorithm::Ed25519 => {},
                PublicKeyAlgorithm::RSAEncryptSign => {},
                t => return Err(Error::UnsupportedPublicKey(t))
            }
            match hash_algo {
                HashAlgorithm::SHA256 => {},
                t => return Err(Error::UnsupportedHash(t))
            }
            debug!("{:?} {:?} {:?}", sigtype, pk_algo, hash_algo);

            let mut hashed_subpacket = try!(body.read_string());
            let initial_len = initial_body.len() - body.len();
            debug!("initial_len: {:?}", initial_len);
            let mut unhashed_subpacket = try!(body.read_string());

            while hashed_subpacket.len() > 0 {
                let sub = try!(Subpacket::read(&mut hashed_subpacket));
                debug!("hashed subpakcet: {:?}", sub);
            }
            while unhashed_subpacket.len() > 0 {
                let sub = try!(Subpacket::read(&mut unhashed_subpacket));
                debug!("unhashed subpacket: {:?}", sub);
            }

            let left_0 = try!(body.read_u8());
            let left_1 = try!(body.read_u8());
            debug!("{:?} {:?}", &initial_body[0..initial_len], data);
            let digest = sha256_version4(data, &initial_body[0..initial_len]);
            if digest[0] != left_0 || digest[1] != left_1 {
                debug!("digest {:?}, {:?} {:?}", digest, left_0, left_1);
                return Ok(false);
            }

            (hash_algo, digest)

        } else {
            return Err(Error::UnknownSignatureVersion(version))
        };

        // Read sig
        let mut signature = Vec::new();

        while body.len() > 0 {
            if body.len() < 2 {
                debug!("{:?}", body);
            }
            let next_mpi = try!(body.read_mpi());
            debug!("{:?}", next_mpi.to_hex());
            signature.extend(next_mpi);
        }

        self.verify_signature(hash_algo, &digest, &signature)
    }
}


const VERSION: u8 = 4;


macro_rules! write_subpackets (
    ($buffer:expr, $sub:expr) => { {
        let n0 = $buffer.len();
        $buffer.extend(b"\0\0");
        $sub;
        let n1 = $buffer.len();
        BigEndian::write_u16(&mut $buffer[ n0 ..], (n1-n0-2) as u16);
    } }
);


impl SecretKey {
    pub fn sign(&self,
                buffer: &mut Vec<u8>,
                data: &[u8],
                signature_type: Type,
                hashed_subpackets: &[Subpacket],
                unhashed_subpackets: &[Subpacket])
                -> Result<(), Error> {
        
        let i0 = buffer.len();
        try!(buffer.write_u8(VERSION));
        try!(buffer.write_u8(signature_type as u8));
        try!(buffer.write_u8(PublicKeyAlgorithm::Ed25519 as u8));
        try!(buffer.write_u8(HashAlgorithm::SHA256 as u8));

        // Subpackets
        write_subpackets!(buffer, {
            // Write all hashed subpackets.
            for p in hashed_subpackets {
                try!(p.write(buffer))
            }
        });

        let i1 = buffer.len();

        // Write unhashed subpackets.
        write_subpackets!(buffer, {
            for p in unhashed_subpackets {
                try!(p.write(buffer))
            }
        });

        let digest = sha256_version4(data, &buffer[i0 .. i1]);
        // Leftmost 16 bits.
        try!(buffer.write_u8(digest[0]));
        try!(buffer.write_u8(digest[1]));

        match *self {
            SecretKey::RSAEncryptSign(ref sk) => {

                let sig = try!(sk.sign(hash::Type::SHA256, &digest));
                debug!("writing RSA signature {:?}", sig);
                try!(buffer.write_mpi(sig.len() << 3, &sig));
                Ok(())
            },
            SecretKey::Ed25519 { ref sk,.. } => {
                
                let mut sig = [0; sodium::ed25519::SIGNATUREBYTES];
                sodium::ed25519::sign_detached(&mut sig, &digest, sodium::ed25519::SecretKey(sk));
                try!(buffer.write_mpi(sig.len() << 3, &sig));
                Ok(())

            }
        }
    }
}


bitflags! {
    pub flags KeyFlags: u8 {
        const MAY_CERTIFY_KEYS = 0x1,
        const MAY_SIGN_DATA = 0x2,
        const MAY_ENCRYPT_COMMUNICATIONS = 0x4,
        const MAY_ENCRYPT_STORAGE = 0x8,
        const PRIV_MAY_HAVE_BEEN_SPLIT = 0x10,
        const MAY_AUTH = 0x20,
        const MORE_THAN_ONE_OWNER = 0x80,
    }
}

bitflags! {
    pub flags KeyServerFlags: u8 {
        const NO_MODIFY = 0x80,
    }
}

bitflags! {
    pub flags Features: u8 {
        const MODIFICATION_DETECTION = 0x1,
    }
}

bitflags! {
    pub flags Class: u8 {
        const SENSITIVE = 0xC0,
    }
}

bitflags! {
    pub flags NotationFlags: u32 {
        const HUMAN_READABLE = 0x80000000,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RevocationCode {
    NoReason = 0,
    Superseeded = 1,
    Compromised = 2,
    Retired = 3,
    InvalidUserID = 32,
}

impl RevocationCode {
    fn from_byte(x:u8) -> Result<RevocationCode, Error> {
        match x {
            0 => Ok(RevocationCode::NoReason),
            1 => Ok(RevocationCode::Superseeded),
            2 => Ok(RevocationCode::Compromised),
            3 => Ok(RevocationCode::Retired),
            32 => Ok(RevocationCode::InvalidUserID),
            _ => Err(Error::UnknownRevocationCode(x))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Subpacket<'a> {
    SignatureCreationTime(u32),
    SignatureExpirationTime(u32),
    ExportableCertification(bool),
    TrustSignature { level: u8 },
    RegularExpression(&'a [u8]),
    Revocable(bool),
    KeyExpirationTime(u32),
    PreferredSymmetricAlgorithm(&'a [SymmetricKeyAlgorithm]),
    RevocationKey { class:Class, pk_algo:PublicKeyAlgorithm, fingerprint: &'a[u8] },
    Issuer([u8;8]),
    NotationData { flags: NotationFlags, name:&'a str, value: &'a[u8] },
    PreferredHashAlgorithm(&'a[HashAlgorithm]),
    PreferredCompressionAlgorithm(&'a[CompressionAlgorithm]),
    KeyServerPreferences(KeyServerFlags),
    PreferredKeyServer(&'a str),
    PrimaryUserID(bool),
    PolicyURI(&'a str),
    KeyFlags(KeyFlags),
    SignersUserID(&'a [u8]),
    ReasonForRevocation { code: RevocationCode, reason:&'a str },
    Features(Features),
    SignatureTarget { pk_algo: PublicKeyAlgorithm, hash_algo:HashAlgorithm, hash: &'a[u8] },
    EmbeddedSignature(&'a[u8]),
}


impl<'a> Subpacket<'a> {

    fn read(packet: &mut &'a [u8]) -> Result<Subpacket<'a>, Error> {
        let p0 = try!(packet.read_u8()) as usize;
        let len = try!(read_length(p0, packet));
        if len <= packet.len() {
            let (mut a, b) = packet.split_at(len);
            *packet = b;

            match try!(a.read_u8()) {
                2 => Ok(Subpacket::SignatureCreationTime(try!(a.read_u32::<BigEndian>()))),
                3 => Ok(Subpacket::SignatureExpirationTime(try!(a.read_u32::<BigEndian>()))),
                4 => Ok(Subpacket::ExportableCertification(try!(a.read_u8()) == 1)),
                5 => Ok(Subpacket::TrustSignature { level: try!(a.read_u8()) }),
                6 => Ok(Subpacket::RegularExpression(a)),
                7 => Ok(Subpacket::Revocable(try!(a.read_u8()) == 1)),
                9 => Ok(Subpacket::KeyExpirationTime(try!(a.read_u32::<BigEndian>()))),
                11 => Ok(Subpacket::PreferredSymmetricAlgorithm(SymmetricKeyAlgorithm::from_slice(a))),
                12 => {
                    let class = try!(a.read_u8());
                    let algo = try!(PublicKeyAlgorithm::from_byte(try!(a.read_u8())));
                    Ok(Subpacket::RevocationKey {
                        class: Class::from_bits_truncate(class),
                        pk_algo: algo,
                        fingerprint: a
                    })
                },
                16 => {
                    let mut issuer = [0;8];
                    issuer.clone_from_slice(a);
                    Ok(Subpacket::Issuer(issuer))
                },
                20 => {
                    let flags = NotationFlags::from_bits_truncate(try!(a.read_u32::<BigEndian>()));
                    let name_len = try!(a.read_u16::<BigEndian>());
                    let value_len = try!(a.read_u16::<BigEndian>());
                    let (name, value) = a.split_at(name_len as usize);
                    assert_eq!(value.len(), value_len as usize);
                    Ok(Subpacket::NotationData {
                        flags: flags,
                        name: try!(std::str::from_utf8(name)),
                        value: value
                    })
                },
                21 => Ok(Subpacket::PreferredHashAlgorithm(HashAlgorithm::from_slice(a))),
                22 => Ok(Subpacket::PreferredCompressionAlgorithm(CompressionAlgorithm::from_slice(a))),
                23 => Ok(Subpacket::KeyServerPreferences(KeyServerFlags::from_bits_truncate(try!(a.read_u8())))),
                24 => Ok(Subpacket::PreferredKeyServer(try!(std::str::from_utf8(a)))),
                25 => Ok(Subpacket::PrimaryUserID(try!(a.read_u8()) == 1)),
                26 => Ok(Subpacket::PolicyURI(try!(std::str::from_utf8(a)))),
                27 => Ok(Subpacket::KeyFlags(KeyFlags::from_bits_truncate(try!(a.read_u8())))),
                28 => Ok(Subpacket::SignersUserID(a)),
                29 => {
                    let code = try!(RevocationCode::from_byte(try!(a.read_u8())));
                    let reason = try!(std::str::from_utf8(a));
                    Ok(Subpacket::ReasonForRevocation {
                        code: code,
                        reason: reason
                    })
                },
                30 => Ok(Subpacket::Features(Features::from_bits_truncate(try!(a.read_u8())))),
                31 => {
                    let algo = try!(PublicKeyAlgorithm::from_byte(try!(a.read_u8())));
                    let hash = try!(HashAlgorithm::from_byte(try!(a.read_u8())));
                    Ok(Subpacket::SignatureTarget {
                        pk_algo: algo,
                        hash_algo: hash,
                        hash: a
                    })
                },
                32 => Ok(Subpacket::EmbeddedSignature(a)),
                t => {
                    Err(Error::UnknownSubpacketType(t))
                }
            }
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }

    fn write<W:Write>(&self, w:&mut W) -> Result<(), Error> {
        match *self {
            Subpacket::SignatureCreationTime(time) => try!(write_u32(w, 2, time)),
            Subpacket::SignatureExpirationTime(time) => try!(write_u32(w, 3, time)),
            Subpacket::ExportableCertification(b) => try!(write_bool(w, 4, b)),
            Subpacket::TrustSignature { level } => try!(write_u8(w, 5, level)),
            Subpacket::RegularExpression(b) => try!(write_bytes(w, 6, b)),
            Subpacket::Revocable(b) => try!(write_bool(w, 7, b)),
            Subpacket::KeyExpirationTime(time) => try!(write_u32(w, 9, time)),
            Subpacket::PreferredSymmetricAlgorithm(p) => try!(write_bytes(w, 11, to_slice(p))),
            Subpacket::RevocationKey { class, pk_algo, ref fingerprint } => {
                try!(write_len(w, 23));
                try!(w.write_u8(12));
                try!(w.write_u8(class.bits()));
                try!(w.write_u8(pk_algo as u8));
                try!(w.write(fingerprint));
            },
            Subpacket::Issuer(ref b) => try!(write_bytes(w, 16, b.as_ref())),
            Subpacket::NotationData{ flags, name, value } => {
                try!(write_len(w, 9 + name.len() + value.len()));
                try!(w.write_u8(20));
                try!(w.write_u32::<BigEndian>(flags.bits()));
                try!(w.write_u16::<BigEndian>(name.len() as u16));
                try!(w.write_u16::<BigEndian>(value.len() as u16));
                try!(w.write(name.as_ref()));
                try!(w.write(value));
            },
            Subpacket::PreferredHashAlgorithm(p) => try!(write_bytes(w, 21, to_slice(p))),
            Subpacket::PreferredCompressionAlgorithm(p) => try!(write_bytes(w, 22, to_slice(p))),
            Subpacket::KeyServerPreferences(flags) => try!(write_u8(w, 23, flags.bits())),
            Subpacket::PreferredKeyServer(b) => try!(write_bytes(w, 24, b.as_ref())),
            Subpacket::PrimaryUserID(b) => try!(write_bool(w, 25, b)),
            Subpacket::PolicyURI(b) => try!(write_bytes(w, 26, b.as_ref())),
            Subpacket::KeyFlags(flags) => try!(write_u8(w, 27, flags.bits())),
            Subpacket::SignersUserID(b) => try!(write_bytes(w, 28, b)),
            Subpacket::ReasonForRevocation { code, reason } => {
                try!(write_len(w, 2 + reason.len()));
                try!(w.write_u8(29));
                try!(w.write_u8(code as u8));
                try!(w.write(reason.as_ref()));
            },
            Subpacket::Features(flags) => try!(write_u8(w, 30, flags.bits())),
            Subpacket::SignatureTarget{ pk_algo, hash_algo, ref hash } => {

                try!(write_len(w, 3 + hash.len()));
                try!(w.write_u8(31));
                try!(w.write_u8(pk_algo as u8));
                try!(w.write_u8(hash_algo as u8));
                try!(w.write(hash));
            },
            Subpacket::EmbeddedSignature(b) => try!(write_bytes(w, 32, b)),
        }
        Ok(())
    }


}


/// The `len` argument must include the packet type.
fn write_len<W:Write>(w:&mut W, len:usize) -> Result<(), Error> {
    if len < 192 {
        try!(w.write_u8(len as u8));
    } else if len <= 8383 {

        let p0 = ((len - 192) >> 8) + 192;
        let p1 = (len - 192) & 0xff;
        try!(w.write_u8(p0 as u8));
        try!(w.write_u8(p1 as u8));
    } else {
        try!(w.write_u8(0xff));
        try!(w.write_u32::<BigEndian>(len as u32));
    }
    Ok(())
}

fn write_u32<W:Write>(w:&mut W, typ: u8, x: u32) -> Result<(), Error> {
    try!(write_len(w, 5));
    try!(w.write_u8(typ));
    try!(w.write_u32::<BigEndian>(x));
    Ok(())
}

fn write_bool<W:Write>(w:&mut W, typ: u8, x: bool) -> Result<(), Error> {
    try!(write_len(w, 2));
    try!(w.write_u8(typ));
    try!(w.write_u8(if x { 1 } else { 0 }));
    Ok(())
}

fn write_bytes<W:Write>(w:&mut W, typ: u8, x: &[u8]) -> Result<(), Error> {
    try!(write_len(w, 1+x.len()));
    try!(w.write_u8(typ));
    try!(w.write(x));
    Ok(())
}

fn write_u8<W:Write>(w:&mut W, typ: u8, x: u8) -> Result<(), Error> {
    try!(write_len(w, 2));
    try!(w.write_u8(typ));
    try!(w.write_u8(x));
    Ok(())
}
