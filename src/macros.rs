static HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
#[allow(clippy::zero_prefixed_literal)]
static HEX_INVERSE: [u8; 128] = {
    const __: u8 = 255;
    [
        //  1  2  3   4  5  6  7   8  9  A  B   C  D  E  F
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 0
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 1
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 2
        00, 01, 02, 03, 04, 05, 06, 07, 08, 09, __, __, __, __, __, __, // 3
        __, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __, // 4
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 5
        __, 10, 11, 12, 13, 14, 15, __, __, __, __, __, __, __, __, __, // 6
        __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 7
    ]
};

macro_rules! write_hex {
    ($input:expr, $output:expr, $bytelen:expr) => {{
        assert_eq!($input.len(), $bytelen);
        if $output.len() != $bytelen * 2 {
            Err(crate::error::ChorusError::BufferTooSmall.into())
        } else {
            for (i, byte) in $input.iter().enumerate() {
                $output[i * 2] = crate::HEX_CHARS[((byte & 0xF0) >> 4) as usize];
                $output[i * 2 + 1] = crate::HEX_CHARS[(byte & 0x0F) as usize];
            }
            Ok(())
        }
    }};
}

macro_rules! read_hex {
    ($input:expr, $output:expr, $bytelen:expr) => {{
        assert_eq!($output.len(), $bytelen);
        if $input.len() != $bytelen * 2 {
            Err(Into::<crate::error::Error>::into(crate::error::ChorusError::EndOfInput))
        } else {
            let mut i = 0;
            loop {
                let high = crate::HEX_INVERSE[$input[i * 2] as usize];
                if high == 255 {
                    break Err(crate::error::ChorusError::BadHexInput.into());
                }
                let low = crate::HEX_INVERSE[$input[i * 2 + 1] as usize];
                if low == 255 {
                    break Err(crate::error::ChorusError::BadHexInput.into());
                }
                $output[i] = high * 16 + low;
                i += 1;
                if i == $bytelen {
                    break Ok(());
                }
            }
        }
    }};
}

macro_rules! parse_u16 {
    ($input:expr, $start:expr) => {
        u16::from_ne_bytes($input[$start .. $start+2].try_into().unwrap())
    }
}

macro_rules! parse_u32 {
    ($input:expr, $start:expr) => {
        u32::from_ne_bytes($input[$start .. $start+4].try_into().unwrap())
    }
}

macro_rules! parse_u64 {
    ($input:expr, $start:expr) => {
        u64::from_ne_bytes($input[$start .. $start+8].try_into().unwrap())
    }
}
