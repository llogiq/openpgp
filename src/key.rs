use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt, ByteOrder};
use super::*;
use super::sodium;

use std::io::{Read, Write};
use openssl;
use std::cmp::min;
use std::num::Wrapping;
use algorithm::*;

use encoding::{ReadValue, WriteValue};


pub enum PublicKey {
    RSAEncryptSign(openssl::crypto::rsa::RSA),
    Ed25519(sodium::ed25519::OwnedPublicKey),
}


pub enum SecretKey {
    RSAEncryptSign(openssl::crypto::rsa::RSA),
    Ed25519 {
        pk: sodium::ed25519::OwnedPublicKey,
        sk: sodium::ed25519::OwnedSecretKey,
    },
}


fn write_rsa_public_key<W: Write>(w: &mut W, k: &openssl::crypto::rsa::RSA) -> Result<(), Error> {
    try!(w.write_u8(PublicKeyAlgorithm::RSAEncryptSign as u8));
    let n = k.n().unwrap();
    let e = k.e().unwrap();
    let n_v = n.to_vec();
    let e_v = e.to_vec();
    try!(w.write_mpi(n.num_bits() as usize, &n_v));
    try!(w.write_mpi(e.num_bits() as usize, &e_v));
    Ok(())
}

fn write_ed25519_public_key<W: Write>(w: &mut W,
                                      k: &sodium::ed25519::OwnedPublicKey)
                                      -> Result<(), Error> {
    try!(w.write_u8(PublicKeyAlgorithm::Ed25519 as u8));
    try!(w.write_u8(ED25519_OID.len() as u8));
    try!(w.write(ED25519_OID));
    let mut mpi = [0; 33];
    mpi[0] = 0x40;
    (&mut mpi[1..]).clone_from_slice(k);
    try!(w.write_mpi(263, &mpi));
    Ok(())
}


const PK_VERSION: u8 = 4;
const ED25519_OID: &'static [u8] = &[43, 6, 1, 4, 1, 218, 71, 15, 1];
// Public key packets.
impl PublicKey {
    pub fn read(body: &mut &[u8]) -> Result<(u32, PublicKey), Error> {
        // signature::read(p.body, contents).unwrap()
        let version = try!(body.read_u8());
        assert_eq!(version, PK_VERSION);
        let creation_time = try!(body.read_u32::<BigEndian>());
        let algo = try!(PublicKeyAlgorithm::from_byte(try!(body.read_u8())));
        match algo {
            PublicKeyAlgorithm::Ed25519 => {
                // https://trac.tools.ietf.org/id/draft-koch-eddsa-for-openpgp-04.html
                let oid_len = try!(body.read_u8()) as usize;
                let (oid, b) = body.split_at(oid_len);
                *body = b;

                assert_eq!(oid, ED25519_OID);
                let mut pk = try!(body.read_mpi());
                assert_eq!(try!(pk.read_u8()), 0x40);

                Ok((creation_time, PublicKey::Ed25519(sodium::ed25519::PublicKey(pk).to_owned())))

            }
            PublicKeyAlgorithm::RSAEncryptSign => {
                use openssl::crypto::rsa::*;
                use openssl::bn::BigNum;
                let n = try!(body.read_mpi());
                let n = try!(BigNum::new_from_slice(n));
                let e = try!(body.read_mpi());
                let e = try!(BigNum::new_from_slice(e));
                Ok((creation_time,
                    PublicKey::RSAEncryptSign(try!(RSA::from_public_components(n, e)))))
            }
            p => Err(Error::UnsupportedPublicKey(p)),
        }
    }

    pub fn write<W: Write>(w: &mut W, k: &PublicKey, creation_time: u32) -> Result<(), Error> {
        try!(w.write_u8(PK_VERSION));
        try!(w.write_u32::<BigEndian>(creation_time));
        match *k {
            PublicKey::RSAEncryptSign(ref k) => try!(write_rsa_public_key(w, k)),
            PublicKey::Ed25519(ref k) => try!(write_ed25519_public_key(w, k)),
        }
        Ok(())
    }
}





fn generate_key(hash_algo: HashAlgorithm, salt: &[u8], c: u8, password: &[u8]) -> Vec<u8> {
    debug!("generate_key: {:?} {:?} {:?}", salt, c, password);
    let c = c as u32;
    let count = (16 + (c & 15)) << ((c >> 4) + 6);
    let count = count as usize;
    let mut s = salt.to_vec();
    s.extend(password);
    use openssl::crypto::hash::{Hasher, Type};
    let mut hasher = match hash_algo {
        HashAlgorithm::SHA1 => Hasher::new(Type::SHA1),
        HashAlgorithm::SHA256 => Hasher::new(Type::SHA256),
        _ => unimplemented!(),
    };
    hasher.write(&s).unwrap();
    let mut byte_count = s.len();;

    while byte_count < count - s.len() {
        hasher.write_all(&s).unwrap();
        byte_count += s.len()
    }
    let s = &s[0..min(s.len(), count - byte_count)];
    hasher.write_all(&s).unwrap();
    hasher.finish()
}
// Secret key packets.
impl SecretKey {
    pub fn read<'a>(body: &mut &'a [u8], password: &[u8]) -> Result<(u32, SecretKey), Error> {

        let (creation_time, public_key) = try!(PublicKey::read(body));

        let string_to_key = try!(body.read_u8());
        if string_to_key >= 0xfe {
            let sym_algo = try!(SymmetricKeyAlgorithm::from_byte(try!(body.read_u8())));
            match sym_algo {
                SymmetricKeyAlgorithm::AES128 => {}
                _ => unimplemented!(),
            }
            match try!(body.read_u8()) {
                0 => {
                    // simple s2k
                    unimplemented!()
                }
                1 => unimplemented!(),
                3 => {
                    let hash_algo = try!(HashAlgorithm::from_byte(try!(body.read_u8())));
                    match hash_algo {
                        HashAlgorithm::SHA1 | HashAlgorithm::SHA256 => {}
                        _ => unimplemented!(),
                    }


                    let (salt, b) = body.split_at(8);
                    *body = b;
                    let c = try!(body.read_u8());
                    let key = generate_key(hash_algo, salt, c, password);
                    let v = {
                        use openssl::crypto::symm::*;
                        let (iv, b) = body.split_at(16);
                        *body = b;
                        decrypt(Type::AES_128_CFB128, &key[0..16], &iv, body)
                    };

                    let mut s = &v[..];
                    if string_to_key == 0xfe {
                        use openssl::crypto::hash::{hash, Type};
                        let (a, b) = s.split_at(s.len() - 20);
                        assert_eq!(b, &hash(Type::SHA1, a)[..])
                    } else {
                        let mut checksum: Wrapping<u16> = Wrapping(0);
                        let (a, mut b) = s.split_at(s.len() - 2);
                        for &byte in a {
                            checksum += Wrapping(byte as u16)
                        }
                        assert_eq!(checksum.0, try!(b.read_u16::<BigEndian>()))
                    }

                    match public_key {

                        PublicKey::RSAEncryptSign(ref pk) => {
                            use openssl::crypto::rsa::RSA;
                            use openssl::bn::BigNum;
                            let d = BigNum::new_from_slice(try!(s.read_mpi())).unwrap();
                            let p = BigNum::new_from_slice(try!(s.read_mpi())).unwrap();
                            let q = BigNum::new_from_slice(try!(s.read_mpi())).unwrap();
                            let _ = try!(s.read_mpi());

                            let mut p_1 = p.clone();
                            p_1.sub_word(1).unwrap();
                            let dp = d.checked_nnmod(&p_1).unwrap();

                            let mut q_1 = q.clone();
                            q_1.sub_word(1).unwrap();

                            let dq = d.checked_nnmod(&q_1).unwrap();
                            let di = q_1.checked_mod_inv(&p).unwrap();

                            Ok((creation_time, SecretKey::RSAEncryptSign(
                                RSA::from_private_components(
                                    pk.n().unwrap(),
                                    pk.e().unwrap(),
                                    d, p, q, dp, dq, di
                                ).unwrap()
                            )))
                        }
                        PublicKey::Ed25519(pk) => {
                            let sk = try!(s.read_mpi());
                            Ok((creation_time,
                                SecretKey::Ed25519 {
                                sk: sodium::ed25519::SecretKey(sk).to_owned(),
                                pk: pk,
                            }))
                        }
                    }
                }
                _ => unimplemented!(),
            }
        } else {
            // cleartext secret key.
            unimplemented!()
        }
    }

    pub fn write<W: Write>(&self,
                           w: &mut W,
                           creation_time: u32,
                           algo: SymmetricKeyAlgorithm,
                           password: &[u8])
                           -> Result<(), Error> {

        let hash_algorithm = HashAlgorithm::SHA256;

        // Public key
        try!(w.write_u8(PK_VERSION));
        try!(w.write_u32::<BigEndian>(creation_time));
        match *self {
            SecretKey::RSAEncryptSign(ref k) => try!(write_rsa_public_key(w, k)),
            SecretKey::Ed25519 { ref pk, .. } => try!(write_ed25519_public_key(w, pk)),
        }
        // Secret key
        try!(w.write_u8(0xfe));
        try!(w.write_u8(algo as u8));
        try!(w.write_u8(3)); // iterated salted
        try!(w.write_u8(hash_algorithm as u8));
        let mut c = [0; 9 + 16];
        sodium::randombytes::into(&mut c);
        c[8] |= 0x80; // large enough count.
        try!(w.write(&c));
        let key = generate_key(hash_algorithm, &c[..8], c[8], password);

        let mut body = Vec::new();
        match *self {
            SecretKey::RSAEncryptSign(ref k) => {
                let d = k.d().unwrap();
                let p = k.p().unwrap();
                let q = k.q().unwrap();
                let u = p.checked_mod_inv(&q).unwrap();
                try!(body.write_mpi(d.num_bits() as usize, &d.to_vec()));
                try!(body.write_mpi(p.num_bits() as usize, &p.to_vec()));
                try!(body.write_mpi(q.num_bits() as usize, &q.to_vec()));
                try!(body.write_mpi(u.num_bits() as usize, &u.to_vec()));
            }
            SecretKey::Ed25519 { ref sk, .. } => {
                try!(body.write(sk));
            }
        }
        let digest = {
            use openssl::crypto::hash::{hash, Type};
            hash(Type::SHA1, &body)
        };
        body.extend(&digest);

        use openssl::crypto::symm::*;
        try!(w.write(&encrypt(Type::AES_128_CFB128, &key[0..16], &c[9..], &body)));
        Ok(())
    }
}
