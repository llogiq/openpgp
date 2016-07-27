use libc::{c_int, c_ulonglong, size_t};
#[link(name = "sodium")]
extern "C" {
    fn sodium_init() -> c_int;
    fn crypto_hash_sha256(d: *mut u8, m: *const u8, len: c_ulonglong) -> c_int;
    fn crypto_sign_ed25519_verify_detached(sig: *const u8,
                                           m: *const u8,
                                           mlen: c_ulonglong,
                                           pk: *const u8)
                                           -> c_int;
    fn crypto_sign_ed25519_detached(sig: *mut u8,
                                    siglen: *mut c_ulonglong,
                                    m: *const u8,
                                    mlen: c_ulonglong,
                                    sk: *const u8)
                                    -> c_int;
    // fn crypto_sign_ed25519_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    fn randombytes_buf(buf: *mut u8, len: size_t);
}

use std::sync::{Once, ONCE_INIT};
static START: Once = ONCE_INIT;


pub mod sha256 {
    use std;
    use libc::c_ulonglong;
    pub const DIGESTBYTES: usize = 32;
    #[derive(Debug)]
    pub struct Digest([u8; DIGESTBYTES]);
    impl std::ops::Deref for Digest {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }
    pub fn hash(m: &[u8]) -> Digest {
        super::START.call_once(|| unsafe {
            super::sodium_init();
        });
        unsafe {
            let mut d: Digest;
            d = std::mem::uninitialized();
            super::crypto_hash_sha256(d.0.as_mut_ptr(), m.as_ptr(), m.len() as c_ulonglong);
            d
        }
    }
}

pub mod ed25519 {
    use libc::c_ulonglong;
    use std;

    pub const PUBLICKEYBYTES: usize = 32;
    pub const SECRETKEYBYTES: usize = 64;
    pub const SIGNATUREBYTES: usize = 64;
    // pub fn generate_keypair() -> Option<(OwnedPublicKey, OwnedSecretKey)> {
    // super::START.call_once(|| unsafe { super::sodium_init(); });
    // unsafe {
    // let mut pk = [0; PUBLICKEYBYTES];
    // let mut sk = [0; SECRETKEYBYTES];
    // if super::crypto_sign_ed25519_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) == 0 {
    // Some((OwnedPublicKey(pk), OwnedSecretKey(sk)))
    // } else {
    // None
    // }
    // }
    // }
    //
    pub fn sign_detached(sig: &mut [u8], m: &[u8], sk: SecretKey) {
        super::START.call_once(|| unsafe {
            super::sodium_init();
        });
        unsafe {
            assert_eq!(sig.len(), SIGNATUREBYTES);
            let mut siglen: c_ulonglong = 0;
            super::crypto_sign_ed25519_detached(sig.as_mut_ptr(),
                                                &mut siglen,
                                                m.as_ptr(),
                                                m.len() as c_ulonglong,
                                                sk.0.as_ptr());
            assert_eq!(siglen, SIGNATUREBYTES as c_ulonglong);
        }
    }

    pub struct OwnedPublicKey(pub [u8; PUBLICKEYBYTES]);
    impl std::ops::Deref for OwnedPublicKey {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }

    impl<'a> PublicKey<'a> {
        pub fn to_owned(&self) -> OwnedPublicKey {
            let mut p = OwnedPublicKey([0; PUBLICKEYBYTES]);
            p.0.clone_from_slice(self.0);
            p
        }
    }

    pub struct OwnedSecretKey(pub [u8; SECRETKEYBYTES]);
    impl std::ops::Deref for OwnedSecretKey {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }

    pub type Signature<'a> = &'a [u8];
    #[derive(Debug, Copy, Clone)]
    pub struct PublicKey<'a>(pub &'a [u8]);


    pub struct SecretKey<'a>(pub &'a [u8]);
    impl<'a> SecretKey<'a> {
        pub fn to_owned(&self) -> OwnedSecretKey {
            let mut p = OwnedSecretKey([0; SECRETKEYBYTES]);
            p.0.clone_from_slice(self.0);
            p
        }
    }

    pub fn verify_detached(signature: Signature, m: &[u8], pk: PublicKey) -> bool {
        super::START.call_once(|| unsafe {
            super::sodium_init();
        });
        unsafe {
            super::crypto_sign_ed25519_verify_detached(signature.as_ptr(),
                                                       m.as_ptr(),
                                                       m.len() as c_ulonglong,
                                                       pk.0.as_ptr()) == 0
        }
    }

}

pub mod randombytes {
    use libc::size_t;
    pub fn into(buf: &mut [u8]) {
        unsafe {
            super::randombytes_buf(buf.as_mut_ptr(), buf.len() as size_t);
        }
    }
}
