use crate::types::parse::json_parse::*;
use crate::Error;

/// Parses a JSON event from the `input` buffer. Places the parsed event into the `output` buffer.
/// Returns the count of consumed bytes and output bytes
pub fn parse_json_event(input: &[u8], output: &mut [u8]) -> Result<(usize, usize), Error> {
    // Minimum-sized JSON event is 204 characters long
    // NOTE: 152 is the minimum binary event
    if input.len() < 204 {
        return Err(Error::JsonBadEvent("Too Short", 0));
    }

    // This tracks where we are currently looking in the input as we scan forward.
    // It is short for INput POSition.
    let mut inpos = 0;

    // If tags comes before content, content can use this to know where to put itself.
    // This is the length of the tags output section. 0 means it hasn't been written yet.
    let mut tags_size: usize = 0;

    // If content comes before tags, we cannot write it because we don't know how much
    // space Tags will take.  So we instead just remember where the content string
    // begins so we can write it later.
    let mut content_input_start: usize = 0;

    // Remember which fields we have read using bit flags.
    // We must get all seven of these fields for an event to be valid.
    const HAVE_ID: u8 = 0x1 << 0;
    const HAVE_PUBKEY: u8 = 0x1 << 1;
    const HAVE_SIG: u8 = 0x1 << 2;
    const HAVE_CREATED_AT: u8 = 0x1 << 3;
    const HAVE_KIND: u8 = 0x1 << 4;
    const HAVE_CONTENT: u8 = 0x1 << 5;
    const HAVE_TAGS: u8 = 0x1 << 6;
    let mut complete: u8 = 0;

    eat_whitespace(input, &mut inpos);
    verify_char(input, b'{', &mut inpos)?;
    loop {
        eat_whitespace(input, &mut inpos);

        // Presuming that we must have at least one field, we don't have to look
        // for the end of the object yet.

        // Move to the start of the field name
        verify_char(input, b'"', &mut inpos)?;

        // No matter which field is next, we need at least 7 bytes for the smallest
        // field and value: kind":1
        // This allows us to skip length tests below that are shorter than inpos+7
        if inpos + 7 > input.len() {
            return Err(Error::JsonBadEvent("Too Short or Missing Fields", inpos));
        }

        if &input[inpos..inpos + 3] == b"id\"" {
            if complete & HAVE_ID == HAVE_ID {
                return Err(Error::JsonBadEvent("Duplicate id field", inpos));
            }
            inpos += 3;
            eat_colon_with_whitespace(input, &mut inpos)?;
            read_id(input, &mut inpos, &mut output[16..48])?;
            complete |= HAVE_ID;
        } else if &input[inpos..inpos + 4] == b"sig\"" {
            if complete & HAVE_SIG == HAVE_SIG {
                return Err(Error::JsonBadEvent("Duplicate sig field", inpos));
            }
            inpos += 4;
            eat_colon_with_whitespace(input, &mut inpos)?;
            read_sig(input, &mut inpos, output)?;
            complete |= HAVE_SIG;
        } else if &input[inpos..inpos + 5] == b"kind\"" {
            if complete & HAVE_KIND == HAVE_KIND {
                return Err(Error::JsonBadEvent("Duplicate kind field", inpos));
            }
            inpos += 5;
            eat_colon_with_whitespace(input, &mut inpos)?;
            let kind = read_kind(input, &mut inpos)?;
            output[4..6].copy_from_slice(kind.to_ne_bytes().as_slice());
            complete |= HAVE_KIND;
        } else if &input[inpos..inpos + 5] == b"tags\"" {
            if complete & HAVE_TAGS == HAVE_TAGS {
                return Err(Error::JsonBadEvent("Duplicate tags field", inpos));
            }
            inpos += 5;
            eat_colon_with_whitespace(input, &mut inpos)?;
            tags_size = read_tags_array(input, &mut inpos, &mut output[144..])?;
            complete |= HAVE_TAGS;
            if content_input_start != 0 {
                // Content was found earlier than tags.
                // Now that tags have been read, we should read the content
                read_content(input, &mut content_input_start, output, 144 + tags_size)?;
                complete |= HAVE_CONTENT;
            }
        } else if &input[inpos..inpos + 7] == b"pubkey\"" {
            if complete & HAVE_PUBKEY == HAVE_PUBKEY {
                return Err(Error::JsonBadEvent("Duplicate pubkey field", inpos));
            }
            inpos += 7;
            eat_colon_with_whitespace(input, &mut inpos)?;
            read_pubkey(input, &mut inpos, &mut output[48..80])?;
            complete |= HAVE_PUBKEY;
        } else if inpos + 8 <= input.len() && &input[inpos..inpos + 8] == b"content\"" {
            if complete & HAVE_CONTENT == HAVE_CONTENT {
                return Err(Error::JsonBadEvent("Duplicate pubkey field", inpos));
            }
            inpos += 8;
            eat_colon_with_whitespace(input, &mut inpos)?;
            if tags_size == 0 {
                // Oops, we haven't read the tags yet. That means we don't yet know where
                // to place the content.  In this case we just remember the offset where
                // this needs to be done, so we can do this later.
                content_input_start = inpos;
                // skip past it so we can read the subsequent fields
                verify_char(input, b'"', &mut inpos)?;
                burn_string(input, &mut inpos)?;
            } else {
                read_content(input, &mut inpos, output, 144 + tags_size)?;
                complete |= HAVE_CONTENT;
            }
        } else if inpos + 11 <= input.len() && &input[inpos..inpos + 11] == b"created_at\"" {
            if complete & HAVE_CREATED_AT == HAVE_CREATED_AT {
                return Err(Error::JsonBadEvent("Duplicate created_at field", inpos));
            }
            inpos += 11;
            eat_colon_with_whitespace(input, &mut inpos)?;
            let u = read_u64(input, &mut inpos)?;
            output[8..16].copy_from_slice(u.to_ne_bytes().as_slice());
            complete |= HAVE_CREATED_AT;
        } else {
            burn_key_and_value(input, &mut inpos)?;
        }

        // get past the comma, or detect the close brace and exit
        if next_object_field(input, &mut inpos)? {
            break;
        }
    }

    if complete == 0b0111_1111 {
        Ok((
            inpos,
            u32::from_ne_bytes(output[0..4].try_into().unwrap()) as usize,
        ))
    } else {
        Err(Error::JsonBadEvent("Missing Fields", inpos))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_json_event() {
        if 256_u16.to_ne_bytes() == [1, 0] {
            test_parse_json_event_big_endian();
        } else {
            test_parse_json_event_little_endian();
        }
    }

    fn test_parse_json_event_little_endian() {
        let json = br#"{"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"kind":1,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","content":"He got snowed in","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (_insize, size) = parse_json_event(&json[..], &mut buffer).unwrap();
        assert_eq!(size, 372);
        assert_eq!(
            &buffer[0..size],
            &[
                116, 1, 0, 0, // 372 bytes long
                1, 0, // kind 1
                0, 0, // padding
                102, 232, 61, 100, 0, 0, 0, 0, // created at 1681778790
                169, 102, 48, 85, 22, 74, 184, 179, 13, 149, 36, 101, 99, 112, 196, 191, 147, 57,
                59, 176, 81, 183, 237, 244, 85, 111, 64, 197, 41, 141, 192, 199, // id
                238, 17, 165, 223, 244, 12, 25, 165, 85, 244, 31, 228, 43, 72, 240, 14, 97, 140,
                145, 34, 86, 34, 174, 55, 182, 194, 187, 103, 183, 108, 78, 73, // pubkey
                77, 254, 161, 166, 247, 49, 65, 213, 105, 30, 67, 175, 195, 35, 77, 190, 115, 1,
                109, 176, 251, 32, 124, 242, 71, 224, 18, 124, 194, 89, 30, 230, 180, 190, 91, 70,
                34, 114, 3, 10, 155, 222, 117, 136, 42, 174, 129, 15, 53, 150, 130, 177, 182, 206,
                108, 187, 151, 32, 17, 65, 197, 118, 219, 66, // sig
                // 144:
                208, 0, // tags section is 208 bytes long
                3, 0, // there are three tags
                10, 0, // first tag is at offset 10
                28, 0, // second tag is at offset 28
                99, 0, // third tag is at offset 99
                // 154: (144+10)
                2, 0, // the first tag has 2 strings
                6, 0, // the first string is 6 bytes long
                99, 108, 105, 101, 110, 116, // "client"
                6, 0, // the second string is 6 bytes long
                103, 111, 115, 115, 105, 112, // "gossip"
                // 172: (144+28)
                2, 0, // the second tag has two strings
                1, 0,   // the first string is 1 char long
                112, // "p"
                64, 0, // the second string is 64 bytes long
                101, 50, 99, 99, 102, 55, 99, 102, 50, 48, 52, 48, 51, 102, 51, 102, 50, 97, 52,
                97, 53, 53, 98, 51, 50, 56, 102, 48, 100, 101, 51, 98, 101, 51, 56, 53, 53, 56, 97,
                55, 100, 53, 102, 51, 51, 54, 51, 50, 102, 100, 97, 97, 101, 102, 99, 55, 50, 54,
                99, 49, 99, 56, 101,
                98, // "e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"
                // 243: (144+99)
                4, 0, // the third tag has 4 strings
                1, 0,   // the first string is 1 char long
                101, // "e"
                64, 0, // the second string is 64 bytes long
                50, 99, 56, 54, 97, 98, 99, 99, 57, 56, 102, 55, 102, 100, 56, 97, 54, 55, 53, 48,
                97, 97, 98, 56, 100, 102, 54, 99, 49, 56, 54, 51, 57, 48, 51, 102, 49, 48, 55, 50,
                48, 54, 99, 99, 50, 100, 55, 50, 101, 56, 97, 102, 101, 98, 54, 99, 51, 56, 51, 53,
                55, 97, 101,
                100, // "2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"
                30, 0, // the third string is 30 bytes long
                119, 115, 115, 58, 47, 47, 110, 111, 115, 116, 114, 45, 112, 117, 98, 46, 119, 101,
                108, 108, 111, 114, 100, 101, 114, 46, 110, 101, 116,
                47, //  "wss://nostr-pub.wellorder.net/"
                4, 0, // the fourth string is 4 bytes long
                114, 111, 111, 116, // "root"
                // 352: (144+208)
                16, 0, 0, 0, // the content is 16 bytes long
                72, 101, 32, 103, 111, 116, 32, 115, 110, 111, 119, 101, 100, 32, 105,
                110, // "He got snowed in"

                     // 372:
            ]
        );

        // Same event in a different order
        let json2 = br#"{"kind":1,"pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]],"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","content":"He got snowed in"}"#;
        let mut buffer2: Vec<u8> = Vec::with_capacity(4096);
        buffer2.resize(4096, 0);
        let (_insize, size) = parse_json_event(&json2[..], &mut buffer2).unwrap();
        assert_eq!(size, 372);
        assert_eq!(&buffer[..372], &buffer2[..372]);
    }

    fn test_parse_json_event_big_endian() {
        let json = br#"{"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"kind":1,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","content":"He got snowed in","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]]}"#;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (_insize, size) = parse_json_event(&json[..], &mut buffer).unwrap();
        assert_eq!(size, 372);
        assert_eq!(
            &buffer[0..size],
            &[
                0, 0, 1, 116, // 372 bytes long
                0, 1, // kind 1
                0, 0, // padding
                0, 0, 0, 0, 100, 61, 232, 102, // created at 1681778790
                169, 102, 48, 85, 22, 74, 184, 179, 13, 149, 36, 101, 99, 112, 196, 191, 147, 57,
                59, 176, 81, 183, 237, 244, 85, 111, 64, 197, 41, 141, 192, 199, // id
                238, 17, 165, 223, 244, 12, 25, 165, 85, 244, 31, 228, 43, 72, 240, 14, 97, 140,
                145, 34, 86, 34, 174, 55, 182, 194, 187, 103, 183, 108, 78, 73, // pubkey
                77, 254, 161, 166, 247, 49, 65, 213, 105, 30, 67, 175, 195, 35, 77, 190, 115, 1,
                109, 176, 251, 32, 124, 242, 71, 224, 18, 124, 194, 89, 30, 230, 180, 190, 91, 70,
                34, 114, 3, 10, 155, 222, 117, 136, 42, 174, 129, 15, 53, 150, 130, 177, 182, 206,
                108, 187, 151, 32, 17, 65, 197, 118, 219, 66, // sig
                // 144:
                0, 208, // tags section is 208 bytes long
                3, 0, // there are three tags
                0, 10, // first tag is at offset 10
                0, 28, // second tag is at offset 28
                0, 99, // third tag is at offset 99
                // 154: (144+10)
                0, 2, // the first tag has 2 strings
                0, 6, // the first string is 6 bytes long
                99, 108, 105, 101, 110, 116, // "client"
                0, 6, // the second string is 6 bytes long
                103, 111, 115, 115, 105, 112, // "gossip"
                // 172: (144+28)
                0, 2, // the second tag has two strings
                0, 1,   // the first string is 1 char long
                112, // "p"
                0, 64, // the second string is 64 bytes long
                101, 50, 99, 99, 102, 55, 99, 102, 50, 48, 52, 48, 51, 102, 51, 102, 50, 97, 52,
                97, 53, 53, 98, 51, 50, 56, 102, 48, 100, 101, 51, 98, 101, 51, 56, 53, 53, 56, 97,
                55, 100, 53, 102, 51, 51, 54, 51, 50, 102, 100, 97, 97, 101, 102, 99, 55, 50, 54,
                99, 49, 99, 56, 101,
                98, // "e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"
                // 243: (144+99)
                0, 4, // the third tag has 4 strings
                0, 1,   // the first string is 1 char long
                101, // "e"
                0, 64, // the second string is 64 bytes long
                50, 99, 56, 54, 97, 98, 99, 99, 57, 56, 102, 55, 102, 100, 56, 97, 54, 55, 53, 48,
                97, 97, 98, 56, 100, 102, 54, 99, 49, 56, 54, 51, 57, 48, 51, 102, 49, 48, 55, 50,
                48, 54, 99, 99, 50, 100, 55, 50, 101, 56, 97, 102, 101, 98, 54, 99, 51, 56, 51, 53,
                55, 97, 101,
                100, // "2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"
                0, 30, // the third string is 30 bytes long
                119, 115, 115, 58, 47, 47, 110, 111, 115, 116, 114, 45, 112, 117, 98, 46, 119, 101,
                108, 108, 111, 114, 100, 101, 114, 46, 110, 101, 116,
                47, //  "wss://nostr-pub.wellorder.net/"
                0, 4, // the fourth string is 4 bytes long
                114, 111, 111, 116, // "root"
                // 352: (144+208)
                0, 0, 0, 16, // the content is 16 bytes long
                72, 101, 32, 103, 111, 116, 32, 115, 110, 111, 119, 101, 100, 32, 105,
                110, // "He got snowed in"
                     // 372:
            ]
        );

        // Same event in a different order
        let json2 = br#"{"kind":1,"pubkey":"ee11a5dff40c19a555f41fe42b48f00e618c91225622ae37b6c2bb67b76c4e49","created_at":1681778790,"sig":"4dfea1a6f73141d5691e43afc3234dbe73016db0fb207cf247e0127cc2591ee6b4be5b462272030a9bde75882aae810f359682b1b6ce6cbb97201141c576db42","tags":[["client","gossip"],["p","e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"],["e","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","wss://nostr-pub.wellorder.net/","root"]],"id":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","content":"He got snowed in"}"#;
        let mut buffer2: Vec<u8> = Vec::with_capacity(4096);
        buffer2.resize(4096, 0);
        let (_insize, size) = parse_json_event(&json2[..], &mut buffer2).unwrap();
        assert_eq!(size, 372);
        assert_eq!(&buffer[..372], &buffer2[..372]);
    }
}
