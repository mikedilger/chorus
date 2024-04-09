use super::json_escape::json_unescape;
use super::put;
use crate::error::{ChorusError, Error};

#[inline]
pub fn eat_whitespace(input: &[u8], inposp: &mut usize) {
    while *inposp < input.len() && [0x20, 0x09, 0x0A, 0x0D].contains(&input[*inposp]) {
        *inposp += 1;
    }
}

#[inline]
pub fn eat_whitespace_and_commas(input: &[u8], inposp: &mut usize) {
    while *inposp < input.len() && [0x20, 0x09, 0x0A, 0x0D, b','].contains(&input[*inposp]) {
        *inposp += 1;
    }
}

#[inline]
pub fn verify_char(input: &[u8], ch: u8, inposp: &mut usize) -> Result<(), Error> {
    if *inposp >= input.len() {
        Err(ChorusError::JsonBad("Too Short or Missing Fields", *inposp).into())
    } else if input[*inposp] == ch {
        *inposp += 1;
        Ok(())
    } else {
        Err(ChorusError::JsonBadCharacter(input[*inposp] as char, *inposp, ch as char).into())
    }
}

pub fn eat_colon_with_whitespace(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    eat_whitespace(input, inposp);
    verify_char(input, b':', inposp)?;
    eat_whitespace(input, inposp);
    Ok(())
}

pub fn next_object_field(input: &[u8], inposp: &mut usize) -> Result<bool, Error> {
    eat_whitespace(input, inposp);
    // next comes either comma or end brace
    if *inposp >= input.len() {
        return Err(ChorusError::JsonBad("Too short", *inposp).into());
    }
    if input[*inposp] == b'}' {
        *inposp += 1;
        Ok(true)
    } else if input[*inposp] == b',' {
        *inposp += 1;
        Ok(false)
    } else {
        Err(ChorusError::JsonBad("Unexpected char", *inposp).into())
    }
}

pub fn read_id(input: &[u8], inposp: &mut usize, output: &mut [u8]) -> Result<(), Error> {
    if output.len() < 32 {
        return Err(ChorusError::BufferTooSmall.into());
    }
    verify_char(input, b'"', inposp)?;
    if *inposp + 64 >= input.len() {
        return Err(ChorusError::JsonBad("Too short reading id", *inposp).into());
    }
    // Read the hex ID and write the binary ID into the output event structure
    read_hex!(&input[*inposp..*inposp + 64], &mut output[..32], 32)?;
    *inposp += 64;
    verify_char(input, b'"', inposp)?;
    Ok(())
}

pub fn read_pubkey(input: &[u8], inposp: &mut usize, output: &mut [u8]) -> Result<(), Error> {
    if output.len() < 32 {
        return Err(ChorusError::BufferTooSmall.into());
    }
    verify_char(input, b'"', inposp)?;
    if *inposp + 64 >= input.len() {
        return Err(ChorusError::JsonBad("Too short reading pubkey", *inposp).into());
    }
    // Read the hex pubkey and write the binary pubkey into the output event structure
    read_hex!(&input[*inposp..*inposp + 64], &mut output[..32], 32)?;
    *inposp += 64;
    verify_char(input, b'"', inposp)?;
    Ok(())
}

pub fn read_u64(input: &[u8], inposp: &mut usize) -> Result<u64, Error> {
    let mut value: u64 = 0;
    let mut any: bool = false;
    while *inposp < input.len() && b"0123456789".contains(&input[*inposp]) {
        any = true;
        value = (value * 10) + (input[*inposp] - 48) as u64;
        *inposp += 1;
    }
    if !any {
        return Err(ChorusError::JsonBad("Expected a positive integer", *inposp).into());
    }
    Ok(value)
}

pub fn read_kind(input: &[u8], inposp: &mut usize) -> Result<u16, Error> {
    let mut value: u32 = 0;
    let mut any: bool = false;
    while *inposp < input.len() && b"0123456789".contains(&input[*inposp]) {
        any = true;
        value = (value * 10) + (input[*inposp] - 48) as u32;
        *inposp += 1;
    }
    if !any {
        return Err(ChorusError::JsonBad(
            "Kind at must be a positive or zero valued number",
            *inposp,
        )
        .into());
    }
    if value > 65535 {
        Err(ChorusError::JsonBad("Kind larger than 65535", *inposp).into())
    } else {
        Ok(value as u16)
    }
}

// HELP written for event only
// From the outer bracket through to the character after the close outer bracket
// returns the size of data written to the output
pub fn read_tags_array(
    input: &[u8],
    inposp: &mut usize,
    output: &mut [u8],
) -> Result<usize, Error> {
    verify_char(input, b'[', inposp)?; // outer array open brace
    eat_whitespace(input, inposp);

    if output.len() < 4 {
        return Err(ChorusError::BufferTooSmall.into());
    }

    // NOTE: we cannot write any tag strings until after we have counted the tags.
    // (our tags structure is optimized for reading, not writing)
    let num_tags: usize = count_tags(input, *inposp)?;
    put(output, 2, (num_tags as u16).to_ne_bytes().as_slice())?;

    // Case where we have no tags
    if num_tags == 0 {
        put(output, 0, 4_u16.to_ne_bytes().as_slice())?;
        burn_array(input, inposp)?;
        return Ok(4);
    }

    verify_char(input, b'[', inposp)?; // opening brace of first tag
    eat_whitespace(input, inposp);

    let mut tag_num = 0;
    let mut outpos: usize = 4 + num_tags * 2;
    if output.len() < outpos {
        return Err(ChorusError::BufferTooSmall.into());
    }

    loop {
        // Write the offset of this tag
        let offset_slot = 4 + tag_num * 2;
        put(
            output,
            offset_slot,
            (outpos as u16).to_ne_bytes().as_slice(),
        )?;

        // Read the tag (bumps inpos and outpos)
        read_tag(input, inposp, output, &mut outpos)?;
        eat_whitespace(input, inposp);

        // Check what is next
        match input[*inposp] {
            b']' => {
                *inposp += 1;
                if tag_num != num_tags - 1 {
                    panic!("Tag count mismatch");
                }
                break;
            }
            b',' => {
                *inposp += 1;
                eat_whitespace(input, inposp);
                verify_char(input, b'[', inposp)?;
                tag_num += 1;
                if tag_num >= num_tags {
                    panic!("Tag count mismatch");
                }
                eat_whitespace(input, inposp);
            }
            _ => return Err(ChorusError::JsonBad("Tag array bad character", *inposp).into()),
        }
    }

    // Write length of tags section
    put(output, 0, (outpos as u16).to_ne_bytes().as_slice())?;

    Ok(outpos)
}

// From the first inner tag bracket, ending after the outer bracket.
// This just counts the tags, it does not write output or modify the inpos
// This does a quicker pass over the content than actual tag parsing does.
pub fn count_tags(input: &[u8], mut inpos: usize) -> Result<usize, Error> {
    // First non-whitespace character after the opening brace
    match input[inpos] {
        b']' => return Ok(0), // no tags
        b'[' => (),           // expected
        _ => return Err(ChorusError::JsonBad("Tag array bad initial character", inpos).into()),
    }

    let mut count = 1;
    inpos += 1;
    burn_tag(input, &mut inpos)?;
    eat_whitespace(input, &mut inpos);

    loop {
        match input[inpos] {
            b']' => return Ok(count),
            b',' => {
                inpos += 1;
                eat_whitespace(input, &mut inpos);
                verify_char(input, b'[', &mut inpos)?;
                count += 1;
                burn_tag(input, &mut inpos)?;
                eat_whitespace(input, &mut inpos);
            }
            _ => return Err(ChorusError::JsonBad("Tag array bad character", inpos).into()),
        }
    }
}

pub fn read_tag(
    input: &[u8],
    inposp: &mut usize,
    output: &mut [u8],
    outposp: &mut usize,
) -> Result<(), Error> {
    verify_char(input, b'"', inposp)?;

    let countpos = *outposp;
    *outposp += 2;
    let mut num_strings: usize = 1;
    loop {
        // read string
        let (inlen, outlen) = json_unescape(&input[*inposp..], &mut output[*outposp + 2..])?;
        // write the length before it
        put(output, *outposp, (outlen as u16).to_ne_bytes().as_slice())?;
        // bump the outposp past it
        *outposp += 2 + outlen;
        // bump the inpos past the string (and the ending quote which isn't counted in the len)
        *inposp += inlen + 1;

        eat_whitespace(input, inposp);
        match input[*inposp] {
            b',' => {
                *inposp += 1;
                eat_whitespace(input, inposp);
                verify_char(input, b'"', inposp)?;
                num_strings += 1;
                continue;
            }
            b']' => {
                *inposp += 1;
                break;
            }
            _ => return Err(ChorusError::JsonBad("Tag array bad character", *inposp).into()),
        }
    }

    // Write the count of strings at the very start
    put(
        output,
        countpos,
        (num_strings as u16).to_ne_bytes().as_slice(),
    )?;

    Ok(())
}

pub fn read_content(
    input: &[u8],
    inposp: &mut usize,
    output: &mut [u8],
    after_tags: usize,
) -> Result<(), Error> {
    verify_char(input, b'"', inposp)?;

    // Place content 4 bytes beyond tags, to reserve space for content length
    let (inlen, outlen) = json_unescape(&input[*inposp..], &mut output[after_tags + 4..])?;
    *inposp += inlen + 1; // +1 to pass the end quote

    // Write content length
    put(output, after_tags, (outlen as u32).to_ne_bytes().as_slice())?;

    // Write event size
    let event_len = after_tags + 4 + outlen;
    put(output, 0, (event_len as u32).to_ne_bytes().as_slice())?;

    Ok(())
}

// FIXME this is too event-offset specific
pub fn read_sig(input: &[u8], inposp: &mut usize, output: &mut [u8]) -> Result<(), Error> {
    if output.len() < 144 {
        return Err(ChorusError::BufferTooSmall.into());
    }
    verify_char(input, b'"', inposp)?;
    if *inposp + 128 >= input.len() {
        return Err(ChorusError::JsonBad("Too short reading sig", *inposp).into());
    }
    // Read the hex sig and write the binary sig into the output event structure
    read_hex!(&input[*inposp..*inposp + 128], &mut output[80..144], 64)?;
    *inposp += 128;
    verify_char(input, b'"', inposp)?;
    Ok(())
}

// from the character after the start quote
// ending on the character following the end quote
pub fn burn_string(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    while *inposp < input.len() && input[*inposp] != b'"' {
        if input[*inposp] == b'\\' && *inposp + 1 < input.len() {
            *inposp += 2;
        } else {
            *inposp += 1;
        }
    }
    if input[*inposp] == b'"' {
        *inposp += 1;
        Ok(())
    } else {
        Err(ChorusError::JsonBad("Unterminated string", *inposp).into())
    }
}

// from the character after the open brace
// ending on the character following the close brace
pub fn burn_tag(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    eat_whitespace(input, inposp);
    // assuming that every tag must have at least one string
    verify_char(input, b'"', inposp)?;
    burn_string(input, inposp)?;
    eat_whitespace(input, inposp);
    while input[*inposp] == b',' {
        *inposp += 1;
        eat_whitespace(input, inposp);
        verify_char(input, b'"', inposp)?;
        burn_string(input, inposp)?;
        eat_whitespace(input, inposp);
    }
    verify_char(input, b']', inposp)?;
    Ok(())
}

pub fn burn_key_and_value(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    verify_char(input, b'"', inposp)?;
    burn_string(input, inposp)?;
    eat_colon_with_whitespace(input, inposp)?;
    burn_value(input, inposp)?;
    Ok(())
}

// from the character after the open brace
// ending on the character following the close brace
pub fn burn_object(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    loop {
        eat_whitespace_and_commas(input, inposp);

        // Check for the end
        if input[*inposp] == b'}' {
            *inposp += 1;
            return Ok(());
        }

        burn_key_and_value(input, inposp)?;
    }
}

// from the character after the open bracket
// ending on the character following the close bracket
pub fn burn_array(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    loop {
        eat_whitespace_and_commas(input, inposp);

        // Check for the end
        if input[*inposp] == b']' {
            *inposp += 1;
            return Ok(());
        }

        burn_value(input, inposp)?;
    }
}

pub fn burn_value(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    if *inposp >= input.len() {
        return Err(ChorusError::JsonBad("Too short burning an unused JSON value", *inposp).into());
    }
    match input[*inposp] {
        b'"' => {
            *inposp += 1;
            burn_string(input, inposp)?
        }
        b'[' => {
            *inposp += 1;
            burn_array(input, inposp)?
        }
        b'{' => {
            *inposp += 1;
            burn_object(input, inposp)?
        }
        b't' => burn_true(input, inposp)?,
        b'f' => burn_false(input, inposp)?,
        b'n' => burn_null(input, inposp)?,
        b'-' => burn_number(input, inposp)?,
        _ => {
            if b"123456789".contains(&input[*inposp]) {
                burn_number(input, inposp)?
            } else {
                return Err(ChorusError::JsonBad(
                    "Too short burning an unused JSON value",
                    *inposp,
                )
                .into());
            }
        }
    }

    Ok(())
}

pub fn burn_null(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    if *inposp + 4 <= input.len() && &input[*inposp..*inposp + 4] == b"null" {
        *inposp += 4;
        Ok(())
    } else {
        Err(ChorusError::JsonBad("Expected null", *inposp).into())
    }
}

pub fn burn_true(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    if *inposp + 4 <= input.len() && &input[*inposp..*inposp + 4] == b"true" {
        *inposp += 4;
        Ok(())
    } else {
        Err(ChorusError::JsonBad("Expected true", *inposp).into())
    }
}

pub fn burn_false(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    if *inposp + 5 <= input.len() && &input[*inposp..*inposp + 5] == b"false" {
        *inposp += 5;
        Ok(())
    } else {
        Err(ChorusError::JsonBad("Expected false", *inposp).into())
    }
}

pub fn burn_number(input: &[u8], inposp: &mut usize) -> Result<(), Error> {
    // For burning, we don't check validity.
    while *inposp < input.len() && b".+-0123456789abcdefABCDEF_oOxXn".contains(&input[*inposp]) {
        *inposp += 1;
    }
    Ok(())
}
