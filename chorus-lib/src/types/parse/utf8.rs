use crate::error::{ChorusError, Error};

// Reads the next code point if UTF-8, and returns it along with the number of characters
// that make it up.
pub fn next_code_point(input: &[u8]) -> Result<Option<(u32, usize)>, Error> {
    let len = input.len();
    if len < 1 {
        return Ok(None);
    }

    // Decode UTF-8
    let x = input[0];
    if x < 128 {
        return Ok(Some((x as u32, 1)));
    }

    // Multibyte case follows
    // Decode from a byte combination out of: [[[x y] z] w]
    let init = utf8_first_byte(x, 2);
    if len < 2 {
        return Err(ChorusError::Utf8Error.into());
    }
    let y = input[1];
    let mut ch = utf8_acc_cont_byte(init, y);
    if x >= 0xE0 {
        // [[x y z] w] case
        // 5th bit in 0xE0 .. 0xEF is always clear, so `init` is still valid
        if len < 3 {
            return Err(ChorusError::Utf8Error.into());
        }
        let z = input[2];
        let y_z = utf8_acc_cont_byte((y & CONT_MASK) as u32, z);
        ch = init << 12 | y_z;
        if x >= 0xF0 {
            // [x y z w] case
            // use only the lower 3 bits of `init`
            if len < 4 {
                return Err(ChorusError::Utf8Error.into());
            }
            let w = input[3];
            ch = (init & 7) << 18 | utf8_acc_cont_byte(y_z, w);
            Ok(Some((ch, 4)))
        } else {
            Ok(Some((ch, 3)))
        }
    } else {
        Ok(Some((ch, 2)))
    }
}

pub fn encode_utf8(code: u32, dst: &mut [u8]) -> Result<usize, Error> {
    // UTF-8 ranges and tags for encoding characters
    const TAG_CONT: u8 = 0b1000_0000;
    const TAG_TWO_B: u8 = 0b1100_0000;
    const TAG_THREE_B: u8 = 0b1110_0000;
    const TAG_FOUR_B: u8 = 0b1111_0000;
    const MAX_ONE_B: u32 = 0x80;
    const MAX_TWO_B: u32 = 0x800;
    const MAX_THREE_B: u32 = 0x10000;

    let len = unsafe {
        if code < MAX_ONE_B && !dst.is_empty() {
            *dst.get_unchecked_mut(0) = code as u8;
            1
        } else if code < MAX_TWO_B && dst.len() >= 2 {
            *dst.get_unchecked_mut(0) = (code >> 6 & 0x1F) as u8 | TAG_TWO_B;
            *dst.get_unchecked_mut(1) = (code & 0x3F) as u8 | TAG_CONT;
            2
        } else if code < MAX_THREE_B && dst.len() >= 3 {
            *dst.get_unchecked_mut(0) = (code >> 12 & 0x0F) as u8 | TAG_THREE_B;
            *dst.get_unchecked_mut(1) = (code >> 6 & 0x3F) as u8 | TAG_CONT;
            *dst.get_unchecked_mut(2) = (code & 0x3F) as u8 | TAG_CONT;
            3
        } else if dst.len() >= 4 {
            *dst.get_unchecked_mut(0) = (code >> 18 & 0x07) as u8 | TAG_FOUR_B;
            *dst.get_unchecked_mut(1) = (code >> 12 & 0x3F) as u8 | TAG_CONT;
            *dst.get_unchecked_mut(2) = (code >> 6 & 0x3F) as u8 | TAG_CONT;
            *dst.get_unchecked_mut(3) = (code & 0x3F) as u8 | TAG_CONT;
            4
        } else {
            return Err(ChorusError::BufferTooSmall.into());
        }
    };
    Ok(len)
}

/// Returns the initial codepoint accumulator for the first byte.
/// The first byte is special, only want bottom 5 bits for width 2, 4 bits
/// for width 3, and 3 bits for width 4.
#[inline]
const fn utf8_first_byte(byte: u8, width: u32) -> u32 {
    (byte & (0x7F >> width)) as u32
}

/// Returns the value of `ch` updated with continuation byte `byte`.
#[inline]
const fn utf8_acc_cont_byte(ch: u32, byte: u8) -> u32 {
    (ch << 6) | (byte & CONT_MASK) as u32
}

/// Mask of the value bits of a continuation byte.
const CONT_MASK: u8 = 0b0011_1111;

#[cfg(test)]
mod test {
    use super::{encode_utf8, next_code_point};

    #[test]
    fn test_next_code_point() {
        let (codepoint, size) = next_code_point(r#"𝄞"#.as_bytes()).unwrap().unwrap();
        assert_eq!(codepoint, 119070);
        assert_eq!(size, 4);

        let (codepoint, size) = next_code_point(r#"†"#.as_bytes()).unwrap().unwrap();
        assert_eq!(codepoint, 0x2020);
        assert_eq!(size, 3);

        // four codepoints
        let s = [
            0x61, 0xE0, 0xA4, 0xA8, 0xE0, 0xA4, 0xBF, 0xE4, 0xBA, 0x9C, 0xF0, 0x90, 0x82, 0x83,
        ];
        let (codepoint, size) = next_code_point(s.as_slice()).unwrap().unwrap();
        assert_eq!(codepoint, 0x61);
        assert_eq!(size, 1);

        let mut start = size;
        let (codepoint, size) = next_code_point(&s[start..]).unwrap().unwrap();
        assert_eq!(codepoint, 0x928);
        assert_eq!(size, 3);

        start += size;
        let (codepoint, size) = next_code_point(&s[start..]).unwrap().unwrap();
        assert_eq!(codepoint, 0x93F);
        assert_eq!(size, 3);

        start += size;
        let (codepoint, size) = next_code_point(&s[start..]).unwrap().unwrap();
        assert_eq!(codepoint, 0x4E9C);
        assert_eq!(size, 3);

        start += size;
        let (codepoint, size) = next_code_point(&s[start..]).unwrap().unwrap();
        assert_eq!(codepoint, 0x10083);
        assert_eq!(size, 4);

        assert_eq!(next_code_point(&s[0..0]).unwrap(), None);
    }

    #[test]
    fn test_encode_utf8() {
        let mut buffer: Vec<u8> = vec![0, 0, 0, 0];

        assert_eq!(encode_utf8(0x69, &mut buffer).unwrap(), 1);
        assert_eq!(buffer[0], 0x69);

        assert_eq!(encode_utf8(0xEC, &mut buffer).unwrap(), 2);
        assert_eq!(&buffer[0..2], &[0xC3, 0xAC]);

        assert_eq!(encode_utf8(0x5450, &mut buffer).unwrap(), 3);
        assert_eq!(&buffer[0..3], &[0xE5, 0x91, 0x90]);

        assert_eq!(encode_utf8(0x2825F, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer[..], &[0xF0, 0xA8, 0x89, 0x9F]);
    }
}
