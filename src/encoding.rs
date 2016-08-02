use Error;
use std;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::io::Read;

pub trait ReadValue<'a> {
    fn read_string(&mut self) -> Result<&'a [u8], Error>;
    fn read_mpi(&mut self) -> Result<&'a [u8], Error>;
}

pub trait WriteValue {
    fn write_string(&mut self, s: &[u8]) -> Result<(), Error>;
    fn write_mpi(&mut self, bit_len: usize, mpi: &[u8]) -> Result<(), Error>;
}

impl<'a> ReadValue<'a> for &'a [u8] {
    // Not a formal def, mut used many times in the RFC.
    fn read_string(&mut self) -> Result<&'a [u8], Error> {
        let length = (*self).read_u16::<BigEndian>().unwrap() as usize;
        if length <= self.len() {
            let (a, b) = self.split_at(length);
            *self = b;
            Ok(a)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }

    // https://tools.ietf.org/html/rfc4880#section-3.2
    fn read_mpi(&mut self) -> Result<&'a [u8], Error> {
        let length = (*self).read_u16::<BigEndian>().unwrap() as usize;
        let length = (length + 7) >> 3;
        if length <= self.len() {
            let (a, b) = self.split_at(length);
            *self = b;
            Ok(a)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
}


impl<W: std::io::Write> WriteValue for W {
    fn write_string(&mut self, s: &[u8]) -> Result<(), Error> {
        assert!(s.len() <= 0xffff);
        try!(self.write_u16::<BigEndian>(s.len() as u16));
        try!(self.write(s));
        Ok(())
    }

    fn write_mpi(&mut self, bit_len: usize, s: &[u8]) -> Result<(), Error> {
        assert_eq!((bit_len + 7) >> 3, s.len());
        try!(self.write_u16::<BigEndian>(bit_len as u16));
        try!(self.write(s));
        Ok(())
    }
}

pub fn read_length<R: Read>(l0: usize, s: &mut R) -> Result<usize, Error> {
    Ok(if l0 <= 191 {
        l0
    } else if l0 <= 223 {
        let l1 = try!(s.read_u8()) as usize;
        (((l0 - 192) << 8) | l1) + 192
    } else {
        debug_assert!(l0 == 0xff);
        try!(s.read_u32::<BigEndian>()) as usize
    })
}
