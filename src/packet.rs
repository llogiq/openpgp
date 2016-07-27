use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt, ByteOrder};
use std::io::{Write, Read};
use super::*;
use encoding::read_length;

#[cfg(test)]
use rand::Rng;
#[cfg(test)]
use rand;

// https://tools.ietf.org/html/rfc4880#section-4.3
// sed -e "s/ *\(.*\) = \(.*\),/\2 => Some(Packet::\1),/"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    PublicKeyEncryptedSessionKey = 1,
    Signature = 2,
    SymmetricKeyEncryptedSessionKey = 3,
    OnePassSignature = 4,
    SecretKey = 5,
    PublicKey = 6,
    SecretSubkey = 7,
    CompressedData = 8,
    SymmetricallyEncryptedData = 9,
    Marker = 10,
    LiteralData = 11,
    Trust = 12,
    UserID = 13,
    PublicSubkey = 14,
    UserAttribute = 17,
    SymIntData = 18,
    ModificationDetectionCode = 19,
}

impl Tag {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Tag::PublicKeyEncryptedSessionKey),
            2 => Some(Tag::Signature),
            3 => Some(Tag::SymmetricKeyEncryptedSessionKey),
            4 => Some(Tag::OnePassSignature),
            5 => Some(Tag::SecretKey),
            6 => Some(Tag::PublicKey),
            7 => Some(Tag::SecretSubkey),
            8 => Some(Tag::CompressedData),
            9 => Some(Tag::SymmetricallyEncryptedData),
            10 => Some(Tag::Marker),
            11 => Some(Tag::LiteralData),
            12 => Some(Tag::Trust),
            13 => Some(Tag::UserID),
            14 => Some(Tag::PublicSubkey),
            17 => Some(Tag::UserAttribute),
            18 => Some(Tag::SymIntData),
            19 => Some(Tag::ModificationDetectionCode),
            _ => None,
        }
    }
}


// TODO: In the next definition, replace Cow with an iterator returning &[u8] (for partial length).
//
// Problem: we can't read the next packet until we've read all the
// partial packets. The `read_packet` function below is correct, but
// allocates a vector which might get big.

pub fn read<B: Read>(reader: &mut B, body: &mut Vec<u8>) -> Result<Tag, Error> {

    body.clear();

    let tag = try!(reader.read_u8());
    assert_eq!(tag & 0x80, 0x80);

    let is_new_format = tag & 0x40 == 0x40;
    println!("new format: {:?}", is_new_format);

    let tag = if is_new_format {

        let packet_tag = tag & 0x3f;

        let mut l0 = try!(reader.read_u8());
        if l0 >= 224 && l0 < 0xff {
            println!("Partial body length");
            while l0 >= 224 && l0 < 0xff {
                // partial length
                let len = 1 << (l0 & 0x1f);

                // read more len bytes
                let i0 = body.len();
                body.resize(i0 + len, 0);
                try!(reader.read_exact(&mut body[i0..]));
                l0 = try!(reader.read_u8())
            }
            // Last part of the packet
            let len = try!(read_length(l0 as usize, reader));
            let i0 = body.len();
            body.resize(i0 + len, 0);
            try!(reader.read_exact(&mut body[i0..]));

        } else {
            let len = try!(read_length(l0 as usize, reader));
            println!("len = {:?}", len);
            body.resize(len, 0);
            try!(reader.read_exact(&mut body[..]));
        }

        packet_tag

    } else {

        let packet_tag = (tag >> 2) & 0xf;
        println!("packet_tag: {:?}", Tag::from_byte(packet_tag));
        let length_type = tag & 0x3;
        if length_type == 0 {

            let len = try!(reader.read_u8()) as usize;
            body.resize(len, 0);
            try!(reader.read_exact(&mut body[..]));

        } else if length_type == 1 {

            let len = reader.read_u16::<BigEndian>().unwrap() as usize;
            body.resize(len, 0);
            try!(reader.read_exact(&mut body[..]));

        } else if length_type == 2 {

            let len = try!(reader.read_u32::<BigEndian>()) as usize;
            body.resize(len, 0);
            try!(reader.read_exact(&mut body[..]));

        } else {
            try!(reader.read_to_end(body));
        };
        packet_tag

    };
    if let Some(tag) = Tag::from_byte(tag) {
        Ok(tag)
    } else {
        Err(Error::UnknownTag)
    }
}

fn write_packet_<W: Write>(mut w: W,
                           new_format: bool,
                           packet_tag: Tag,
                           contents: &[u8])
                           -> Result<(), Error> {

    if new_format {

        try!(w.write_u8(0xC0 | (packet_tag as u8)));

        if contents.len() <= 191 {

            try!(w.write_u8(contents.len() as u8));

        } else if contents.len() <= 8383 {

            let len = contents.len() - 192;
            try!(w.write_u8(((len >> 8) + 192) as u8));
            try!(w.write_u8(len as u8));

        } else {
            assert!(contents.len() <= 0xffffffff);
            try!(w.write_u8(0xff));
            try!(w.write_u32::<BigEndian>(contents.len() as u32));
        }
        try!(w.write(contents));

    } else {
        // old format packet
        if contents.len() <= 0xff {
            try!(w.write_u8(0x80 | ((packet_tag as u8) << 2) | 0));
            try!(w.write_u8(contents.len() as u8));
        } else if contents.len() <= 0xffff {
            try!(w.write_u8(0x80 | ((packet_tag as u8) << 2) | 1));
            try!(w.write_u16::<BigEndian>(contents.len() as u16));
        } else {
            assert!(contents.len() <= 0xffffffff);
            try!(w.write_u8(0x80 | ((packet_tag as u8) << 2) | 2));
            try!(w.write_u32::<BigEndian>(contents.len() as u32));
        }
        try!(w.write(contents));
    }
    Ok(())
}

#[test]
fn test_packet_formats() {

    let s = rand::thread_rng().gen_iter().take(100).collect::<Vec<u8>>();

    let packet_tag = Tag::Signature;

    let mut v = Vec::new();
    write_packet_(&mut v, true, packet_tag, &s).unwrap();
    {
        let mut slice = &v[..];
        let mut body = Vec::new();
        let tag = read(&mut slice, &mut body).unwrap();
        assert_eq!(&body[..], &s[..]);
        assert_eq!(tag, packet_tag);
    }
    v.clear();
    write_packet_(&mut v, false, packet_tag, &s).unwrap();
    {
        let mut slice = &v[..];
        let mut body = Vec::new();
        let tag = read(&mut slice, &mut body).unwrap();
        assert_eq!(&body[..], &s[..]);
        assert_eq!(tag, packet_tag);
    }
}

pub fn write_packet<W: Write>(w: W, packet_tag: Tag, contents: &[u8]) -> Result<(), Error> {
    write_packet_(w, true, packet_tag, contents)
}
