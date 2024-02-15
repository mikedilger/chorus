use super::utf8::{encode_utf8, next_code_point};
use crate::error::{ChorusError, Error};

// LITERAL UNESCAPED:   0x20-0x21, 0x23-0x5B, 0x5D-10FFFF
// ESCAPES:     \"  \\  \/  /b  /f  /n  /r  /t
// UTF ESCAPE:  \uXXXX or \uXXXX\uXXXX

#[allow(dead_code)] // FIXME
pub fn json_escape(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    // Write position in the output buffer
    let mut write_pos = 0;

    // closure to output bytes
    let mut output = |s: &[u8]| -> Result<(), Error> {
        if out.len() < write_pos + s.len() {
            Err(ChorusError::BufferTooSmall.into())
        } else {
            out[write_pos..write_pos + s.len()].copy_from_slice(s);
            write_pos += s.len();
            Ok(())
        }
    };

    let mut read_pos: usize = 0;
    while let Some((codepoint, size)) = next_code_point(&input[read_pos..])? {
        if is_safe_char(codepoint) {
            output(&input[read_pos..read_pos + size])?;
        } else {
            match codepoint {
                0x08 => output("\\b".as_bytes())?,
                0x09 => output("\\t".as_bytes())?,
                0x0A => output("\\n".as_bytes())?,
                0x0C => output("\\f".as_bytes())?,
                0x0D => output("\\r".as_bytes())?,
                0x22 => output("\\\"".as_bytes())?,
                0x5C => output("\\\\".as_bytes())?,
                _ => {
                    if codepoint > 0x20 {
                        panic!("unnecessary encoding requested");
                    }
                    output(format!("\\u{:04x}", codepoint).as_bytes())?;
                }
            }
        }
        read_pos += size;
    }

    Ok(write_pos)
}

macro_rules! output_slice {
    ($slice:expr, $out:expr, $pos:expr) => {
        if $out.len() < *$pos + $slice.len() {
            Err(Into::<crate::error::Error>::into(
                crate::error::ChorusError::BufferTooSmall,
            ))
        } else {
            $out[*$pos..*$pos + $slice.len()].copy_from_slice($slice);
            *$pos += $slice.len();
            Ok(())
        }
    };
}

macro_rules! output_byte {
    ($byte:expr, $out:expr, $pos:expr) => {
        if $out.len() < *$pos + 1 {
            Err(Into::<crate::error::Error>::into(
                crate::error::ChorusError::BufferTooSmall,
            ))
        } else {
            unsafe { *$out.get_unchecked_mut(*$pos) = $byte };
            *$pos += 1;
            Ok(())
        }
    };
}

/// This unescapes a JSON string into the output.
///
/// The input should start on the first character of the string, and may extend
/// to the ending double-quote and even further.
///
/// This will return how much input was consumed and how much output was written
/// in that order (input_len, output_len)
pub fn json_unescape(input: &[u8], out: &mut [u8]) -> Result<(usize, usize), Error> {
    const BACKSPACE: u8 = 0x08;
    const FORMFEED: u8 = 0x0C;
    const LINEFEED: u8 = 0x0A;
    const CR: u8 = 0x0D;
    const TAB: u8 = 0x09;
    const QUOTE: u8 = 0x22;
    const BACKSLASH: u8 = 0x5C;
    const SLASH: u8 = 0x2F;

    // Write position in the output buffer
    let mut write_pos: usize = 0;

    let mut inescape: bool = false;
    let mut uescape: Option<(usize, u32)> = None;
    let mut p: usize = 0;
    while let Some((codepoint, size)) = next_code_point(&input[p..])? {
        if inescape {
            inescape = false;
            if codepoint > 255 {
                return Err(ChorusError::JsonEscape.into());
            }
            match codepoint as u8 {
                QUOTE | BACKSLASH | SLASH => {
                    output_slice!(&input[p..p + size], out, &mut write_pos)?
                }
                b'b' => output_byte!(BACKSPACE, out, &mut write_pos)?,
                b'f' => output_byte!(FORMFEED, out, &mut write_pos)?,
                b'n' => output_byte!(LINEFEED, out, &mut write_pos)?,
                b'r' => output_byte!(CR, out, &mut write_pos)?,
                b't' => output_byte!(TAB, out, &mut write_pos)?,
                b'u' => uescape = Some((0, 0)),
                _ => return Err(ChorusError::JsonEscape.into()), // nothing else is a legal escape
            }
        } else if let Some((digit, total)) = uescape {
            // must be a digit
            if !(48..=57).contains(&codepoint) {
                return Err(ChorusError::JsonEscape.into());
            }
            let total = total + ((codepoint - 48) << (4 * (3 - digit)));
            if digit >= 3 {
                if (0xD800..=0xDFFF).contains(&total) {
                    return Err(ChorusError::JsonEscapeSurrogate.into());
                }
                let s = encode_utf8(total, &mut out[write_pos..])?;
                write_pos += s;
                uescape = None;
            } else {
                uescape = Some((digit + 1, total));
            }
        } else if codepoint == 0x5C {
            // backslash
            inescape = true;
        } else if is_safe_char(codepoint) {
            output_slice!(&input[p..p + size], out, &mut write_pos)?;
        } else if codepoint == 0x22 {
            // ending double quote
            break;
        } else {
            return Err(ChorusError::JsonBadStringChar(codepoint).into());
        }
        p += size;
    }

    Ok((p, write_pos))
}

#[inline]
fn is_safe_char(c: u32) -> bool {
    let safe_ranges = [(0x20..=0x21), (0x23..=0x5B), (0x5D..=0x10FFFF)];
    safe_ranges.iter().any(|range| range.contains(&c))
}

#[cfg(test)]
mod test {
    use super::{json_escape, json_unescape};

    #[test]
    fn test_json_escape() {
        let mut buffer: [u8; 255] = [255; 255];

        let input = "hello\t\tworld
!!!";
        let _size = json_escape(input.as_bytes(), &mut buffer).unwrap();
        assert_eq!(&buffer[0..19], br#"hello\t\tworld\n!!!"#);

        let input: [u8; 11] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let _size = json_escape(input.as_slice(), &mut buffer).unwrap();
        assert_eq!(
            &buffer[0..54],
            br#"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n"#
        );

        let input: [u8; 12] = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
        let _size = json_escape(input.as_slice(), &mut buffer).unwrap();
        assert_eq!(
            &buffer[0..64],
            br#"\u000b\f\r\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016"#
        );

        let input: [u8; 4] = [32, 33, 34, 35];
        let _size = json_escape(input.as_slice(), &mut buffer).unwrap();
        assert_eq!(&buffer[0..5], br##" !\"#"##);

        let input: [u8; 1] = [92];
        let _size = json_escape(input.as_slice(), &mut buffer).unwrap();
        assert_eq!(&buffer[0..2], br#"\\"#);
    }

    #[test]
    fn test_json_unescape() {
        let is_ok = |s: &[u8], equals: &[u8]| {
            let mut buffer: Vec<u8> = Vec::with_capacity(1024);
            buffer.resize(1024, 0);
            let r = json_unescape(s, &mut buffer);
            assert!(r.is_ok());
            let (_inlen, outlen) = r.unwrap();
            assert_eq!(outlen, equals.len());
            assert_eq!(&buffer[0..equals.len()], equals);
        };

        let is_err = |s: &[u8]| {
            let mut buffer: Vec<u8> = Vec::with_capacity(1024);
            buffer.resize(1024, 0);
            let r = json_unescape(s, &mut buffer);
            assert!(r.is_err());
        };

        // simple string
        is_ok(&b"abc".as_slice(), b"abc");

        // carraige return
        is_ok(&br#"ab\nc"#.as_slice(), b"ab\nc");

        // escaping a character that is not allowed
        is_err(&br#"ab\zc"#.as_slice());

        // escaping quotes is allowed
        is_ok(&br#" \"abc\" "#.as_slice(), br#" "abc" "#);

        // high character
        is_ok(r#"𝄞"#.as_bytes(), "𝄞".as_bytes());

        // high character is interpreted as these four bytes
        is_ok(r#"𝄞"#.as_bytes(), b"\xF0\x9D\x84\x9E");

        // esacaping a character that is not allowed
        is_err(r#"\𝄞"#.as_bytes());

        // actual unescaped tab is disallowed
        is_err("\t".as_bytes());

        // unicode escape and more
        is_ok(
            r#"{\"name\":\"BagMan\",\"about\":\"Father.\nHusband.\nNerd: \u2020.\"}"#.as_bytes(),
            "{\"name\":\"BagMan\",\"about\":\"Father.\nHusband.\nNerd: †.\"}".as_bytes(),
        );

        // bad unicode escape
        is_err(r#"\u8f00"#.as_bytes());

        // Check output values
        let mut buffer: Vec<u8> = Vec::with_capacity(1024);
        buffer.resize(1024, 0);
        let (inlen, outlen) = json_unescape(br#"the\nclient", "gossip""#, &mut buffer).unwrap();
        assert_eq!(inlen, 11);
        assert_eq!(outlen, 10);
    }
}
