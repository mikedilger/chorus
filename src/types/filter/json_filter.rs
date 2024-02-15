use crate::error::{ChorusError, Error};
use crate::types::parse::json_escape::json_unescape;
use crate::types::parse::json_parse::*;

/// Parses a JSON filter from the `input` buffer. Places the parsed filter into the `output` buffer.
/// Returns the count of consumed bytes and output bytes
pub fn parse_json_filter(input: &[u8], output: &mut [u8]) -> Result<(usize, usize), Error> {
    if input.len() < 2 {
        return Err(ChorusError::JsonBadFilter("Too short", 0).into());
    }

    // This tracks where we are currently looking in the input as we scan forward.
    // It is short for INput POSition.
    let mut inpos = 0;

    // Remember which fields we have read using bit flags.
    // We should only get at maximum one of each
    const HAVE_IDS: u8 = 0x1 << 0;
    const HAVE_AUTHORS: u8 = 0x1 << 1;
    const HAVE_KINDS: u8 = 0x1 << 2;
    const HAVE_LIMIT: u8 = 0x1 << 3;
    const HAVE_SINCE: u8 = 0x1 << 4;
    const HAVE_UNTIL: u8 = 0x1 << 5;
    let mut found: u8 = 0;

    // Remember which tags we have seen
    // We track A-Z in the lower 26 bits, and a-z in the next 26 bits
    let mut found_tags: u64 = 0;
    let letter_to_tag_bit = |letter: u8| -> Option<u64> {
        match letter {
            65..=90 => Some(letter as u64 - 65),
            97..=122 => Some(letter as u64 - 97 + 26),
            _ => None,
        }
    };

    // Start structure with that of an empty filter
    output[0..32].copy_from_slice(&[
        0, 0, // length (we will fill it in later)
        0, 0, // 0 ids
        0, 0, // 0 authors
        0, 0, // 0 kinds
        255, 255, 255, 255, // max limit
        0, 0, 0, 0, // padding
        0, 0, 0, 0, 0, 0, 0, 0, // since 1970
        255, 255, 255, 255, 255, 255, 255, 255, // until max unixtime
    ]);

    let mut end: usize = 32;

    // We just store the position of ids, authors, kinds, and tags
    // and come back to parse them properly again at the end,
    // since we need to write them in a particular order.
    let mut start_ids: Option<usize> = None;
    let mut start_authors: Option<usize> = None;
    let mut start_kinds: Option<usize> = None;
    // Allowing up to 32 tag filter fields (plenty!)
    // (we are not differentiating letters yet, just collecting offsets)
    // (we make the array to avoid allocation)
    let mut num_tag_fields = 0;
    let mut start_tags: [usize; 32] = [usize::MAX; 32];

    eat_whitespace(input, &mut inpos);
    verify_char(input, b'{', &mut inpos)?;
    loop {
        eat_whitespace_and_commas(input, &mut inpos);

        // Check for end
        if input[inpos] == b'}' {
            inpos += 1;
            break;
        }

        verify_char(input, b'"', &mut inpos)?;

        if inpos + 4 <= input.len() && &input[inpos..inpos + 4] == b"ids\"" {
            // Check for duplicate
            if found & HAVE_IDS == HAVE_IDS {
                return Err(ChorusError::JsonBadFilter("Duplicate id field", inpos).into());
            }
            inpos += 4;

            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            // Record for later
            start_ids = Some(inpos);

            // Burn the field
            while inpos < input.len() && input[inpos] != b']' {
                inpos += 1;
            }
            verify_char(input, b']', &mut inpos)?;

            // Mark as found 'ids'  FIXME this dups `start_ids`
            found |= HAVE_IDS;
        } else if inpos + 8 <= input.len() && &input[inpos..inpos + 8] == b"authors\"" {
            // Check for duplicate
            if found & HAVE_AUTHORS == HAVE_AUTHORS {
                return Err(ChorusError::JsonBadFilter("Duplicate authors field", inpos).into());
            }
            inpos += 8;

            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            // Save the input offset for post-processing
            start_authors = Some(inpos);

            // Burn the field
            while inpos < input.len() && input[inpos] != b']' {
                inpos += 1;
            }
            verify_char(input, b']', &mut inpos)?;

            found |= HAVE_AUTHORS;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"kinds\"" {
            // Check for duplicate
            if found & HAVE_KINDS == HAVE_KINDS {
                return Err(ChorusError::JsonBadFilter("Duplicate kinds field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            // Mark this position and bypass this field
            start_kinds = Some(inpos);

            // Burn the field
            while inpos < input.len() && input[inpos] != b']' {
                inpos += 1;
            }
            verify_char(input, b']', &mut inpos)?;

            found |= HAVE_KINDS;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"since\"" {
            // Check for duplicate
            if found & HAVE_SINCE == HAVE_SINCE {
                return Err(ChorusError::JsonBadFilter("Duplicate since field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            let since = read_u64(input, &mut inpos)?;
            output[16..24].copy_from_slice(since.to_ne_bytes().as_slice());

            found |= HAVE_SINCE;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"until\"" {
            // Check for duplicate
            if found & HAVE_UNTIL == HAVE_UNTIL {
                return Err(ChorusError::JsonBadFilter("Duplicate until field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            let until = read_u64(input, &mut inpos)?;
            output[24..32].copy_from_slice(until.to_ne_bytes().as_slice());

            found |= HAVE_UNTIL;
        } else if inpos + 6 <= input.len() && &input[inpos..inpos + 6] == b"limit\"" {
            // Check for duplicate
            if found & HAVE_LIMIT == HAVE_LIMIT {
                return Err(ChorusError::JsonBadFilter("Duplicate limit field", inpos).into());
            }
            inpos += 6;

            eat_colon_with_whitespace(input, &mut inpos)?;
            let limit = read_u64(input, &mut inpos)?;
            let limit: u32 = limit as u32;
            output[8..12].copy_from_slice(limit.to_ne_bytes().as_slice());

            found |= HAVE_LIMIT;
        } else if inpos + 3 <= input.len()
            && input[inpos] == b'#'
            && ((input[inpos + 1] >= 65 && input[inpos + 1] <= 90)
                || (input[inpos + 1] >= 97 && input[inpos + 1] <= 122))
            && input[inpos + 2] == b'"'
        {
            inpos += 1; // pass the hash

            // Mark this position (on the letter itself)
            start_tags[num_tag_fields] = inpos;
            num_tag_fields += 1;

            let letter = input[inpos];
            inpos += 2; // pass the letter and quote

            // Remember we found this tag in the `found_tags` bitfield
            if let Some(bit) = letter_to_tag_bit(letter) {
                if found_tags & bit == bit {
                    return Err(ChorusError::JsonBadFilter("Duplicate tag", inpos).into());
                }
                found_tags |= bit;
            }

            // Burn the rest
            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;
            burn_array(input, &mut inpos)?;
        } else {
            burn_key_and_value(input, &mut inpos)?;
        }
    }

    // Copy ids
    if let Some(mut inpos) = start_ids {
        let mut num_ids: u16 = 0;
        // `inpos` is right after the open bracket of the array
        loop {
            eat_whitespace_and_commas(input, &mut inpos);
            if input[inpos] == b']' {
                break;
            }
            read_id(input, &mut inpos, &mut output[end..])?;
            num_ids += 1;
            end += 32;
        }

        // Write num_ids
        output[2..4].copy_from_slice(num_ids.to_ne_bytes().as_slice());
    }

    // Copy authors
    if let Some(mut inpos) = start_authors {
        let mut num_authors: u16 = 0;
        // `inpos` is right after the open bracket of the array
        loop {
            eat_whitespace_and_commas(input, &mut inpos);
            if input[inpos] == b']' {
                break;
            }
            read_pubkey(input, &mut inpos, &mut output[end..])?;
            num_authors += 1;
            end += 32;
        }

        // write num_authors
        output[4..6].copy_from_slice(num_authors.to_ne_bytes().as_slice());
    }

    // Copy kinds
    if let Some(mut inpos) = start_kinds {
        let mut num_kinds: u16 = 0;
        // `inpos` is right after the open bracket of the array
        loop {
            eat_whitespace_and_commas(input, &mut inpos);
            if input[inpos] == b']' {
                break;
            }
            let u = read_u64(input, &mut inpos)?;
            if u > 65535 {
                return Err(
                    ChorusError::JsonBadFilter("Filter has kind number too large", inpos).into(),
                );
            }
            output[end..end + 2].copy_from_slice((u as u16).to_ne_bytes().as_slice());
            num_kinds += 1;
            end += 2;
        }

        // write num_kinds
        output[6..8].copy_from_slice(num_kinds.to_ne_bytes().as_slice());
    }

    // Copy tags
    {
        let write_tags_start = end;
        // write number of tags
        output[write_tags_start + 2..write_tags_start + 4]
            .copy_from_slice((num_tag_fields as u16).to_ne_bytes().as_slice());
        // bump end past offset fields
        end += 4 + 2 * num_tag_fields;
        // Now pull in each tag
        for w in 0..num_tag_fields {
            // Write it's offset
            output[write_tags_start + 4 + (2 * w)..write_tags_start + 4 + (2 * w) + 2]
                .copy_from_slice(((end - write_tags_start) as u16).to_ne_bytes().as_slice());

            let mut inpos = start_tags[w];
            let letter = input[inpos];

            // bump past count output and write letter
            let countindex = end;
            end += 2;
            output[end..end + 2].copy_from_slice(1_u16.to_ne_bytes().as_slice());
            output[end + 2] = letter;

            // bump past what we just wrote
            end += 3;

            // scan further in input
            inpos += 1; // move off letter
            verify_char(input, b'"', &mut inpos)?;
            eat_colon_with_whitespace(input, &mut inpos)?;
            verify_char(input, b'[', &mut inpos)?;

            let mut count: u16 = 1; // the tag letter itself counts
            loop {
                eat_whitespace_and_commas(input, &mut inpos);
                if input[inpos] == b']' {
                    break;
                }
                verify_char(input, b'"', &mut inpos)?;
                // copy  data
                let (inlen, outlen) = json_unescape(&input[inpos..], &mut output[end + 2..])?;
                // write len
                output[end..end + 2].copy_from_slice((outlen as u16).to_ne_bytes().as_slice());
                end += 2 + outlen;
                inpos += inlen + 1;
                count += 1;
            }

            // write count
            output[countindex..countindex + 2].copy_from_slice(count.to_ne_bytes().as_slice());
        }
        // write length of tags section
        output[write_tags_start..write_tags_start + 2]
            .copy_from_slice(((end - write_tags_start) as u16).to_ne_bytes().as_slice());
    }

    if end > 65535 {
        return Err(ChorusError::JsonBadFilter("Filter is too long", end).into());
    }

    // Write length of filter
    output[..2].copy_from_slice((end as u16).to_ne_bytes().as_slice());

    Ok((inpos, end))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::{Filter, Kind, Pubkey, Tags, TagsIter, TagsStringIter, Time};

    #[test]
    fn test_parse_json_empty_filter() {
        let json = br##"{}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(size, 36);
        assert_eq!(
            &buffer[0..size],
            &[
                36, 0, // length
                0, 0, // 0 ids
                0, 0, // 0 authors
                0, 0, // 0 kinds
                255, 255, 255, 255, // max limit
                0, 0, 0, 0, // padding
                0, 0, 0, 0, 0, 0, 0, 0, // since 1970
                255, 255, 255, 255, 255, 255, 255, 255, // until max unixtime
                4, 0, 0, 0, // empty tags section
            ]
        );
    }

    #[test]
    fn test_parse_json_filter1() {
        let json = br##"{"kinds":[1,30023],"since":1681778790,"authors":["e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"],"until":1704238196,"ids" : [ "7089afc2e77f366bc0fd1662e4048f59f18391c04a35957f21bbd1f3e6a492c4"],"limit":10}"##;
        // ,"#e":"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7"}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, json.len());
        assert_eq!(size, 136);
        assert_eq!(
            &buffer[0..size],
            &[
                136, 0, // length
                1, 0, // 0 ids
                2, 0, // 0 authors
                2, 0, // 0 kinds
                10, 0, 0, 0, // max limit 10
                0, 0, 0, 0, // padding
                102, 232, 61, 100, 0, 0, 0, 0, // since 1681778790
                116, 156, 148, 101, 0, 0, 0, 0, // until 1704238196
                // First ID:
                112, 137, 175, 194, 231, 127, 54, 107, 192, 253, 22, 98, 228, 4, 143, 89, 241, 131,
                145, 192, 74, 53, 149, 127, 33, 187, 209, 243, 230, 164, 146, 196,
                // First author:
                226, 204, 247, 207, 32, 64, 63, 63, 42, 74, 85, 179, 40, 240, 222, 59, 227, 133, 88,
                167, 213, 243, 54, 50, 253, 170, 239, 199, 38, 193, 200, 235,
                // Second author:
                44, 134, 171, 204, 152, 247, 253, 138, 103, 80, 170, 184, 223, 108, 24, 99, 144, 63,
                16, 114, 6, 204, 45, 114, 232, 175, 235, 108, 56, 53, 122, 237, // Kinds,
                1, 0, // 1
                71, 117, // 30023
                4, 0, 0, 0, // empty tags section
            ]
        );
    }

    #[test]
    fn test_parse_json_filter2() {
        let json = br##"{"kinds":[1,30023],"since":1681778790,"authors":["e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"],"until":1704238196,"ids" : [ "7089afc2e77f366bc0fd1662e4048f59f18391c04a35957f21bbd1f3e6a492c4"],"limit":10, "#e":["a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7"]}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, json.len());
        assert_eq!(size, 209);
        assert_eq!(
            &buffer[0..size],
            &[
                209, 0, // length
                1, 0, // 0 ids
                2, 0, // 0 authors
                2, 0, // 0 kinds
                10, 0, 0, 0, // max limit 10
                0, 0, 0, 0, // padding
                102, 232, 61, 100, 0, 0, 0, 0, // since 1681778790
                116, 156, 148, 101, 0, 0, 0, 0, // until 1704238196
                // First ID:
                112, 137, 175, 194, 231, 127, 54, 107, 192, 253, 22, 98, 228, 4, 143, 89, 241, 131,
                145, 192, 74, 53, 149, 127, 33, 187, 209, 243, 230, 164, 146, 196,
                // First author:
                226, 204, 247, 207, 32, 64, 63, 63, 42, 74, 85, 179, 40, 240, 222, 59, 227, 133, 88,
                167, 213, 243, 54, 50, 253, 170, 239, 199, 38, 193, 200, 235,
                // Second author:
                44, 134, 171, 204, 152, 247, 253, 138, 103, 80, 170, 184, 223, 108, 24, 99, 144, 63,
                16, 114, 6, 204, 45, 114, 232, 175, 235, 108, 56, 53, 122, 237, // Kinds,
                1, 0, // 1
                71, 117, // 30023
                // Tag section:
                77, 0, // tags section length is 77
                1, 0, // just one tag
                6, 0, // offset of 0th tag is 6
                // First tag:
                2, 0, // 2 fields
                // Field 1:
                1, 0,   // 1 byte long
                101, // 'e'
                // Field 2:
                64, 0, // 64 bytes long
                97, 57, 54, 54, 51, 48, 53, 53, 49, 54, 52, 97, 98, 56, 98, 51, 48, 100, 57, 53,
                50, 52, 54, 53, 54, 51, 55, 48, 99, 52, 98, 102, 57, 51, 51, 57, 51, 98, 98, 48,
                53, 49, 98, 55, 101, 100, 102, 52, 53, 53, 54, 102, 52, 48, 99, 53, 50, 57, 56,
                100, 99, 48, 99, 55
            ]
        );
    }

    #[test]
    fn test_filter_parse_and_check() {
        let json = br##"{"kinds":[1,5,9,30023],"since":1681778790,"authors":["e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"], "#e":["a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"],"#p":["2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed","2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"]}"##;
        let mut buffer: Vec<u8> = Vec::with_capacity(4096);
        buffer.resize(4096, 0);
        let (consumed, size) = parse_json_filter(&json[..], &mut buffer).unwrap();
        assert_eq!(consumed, json.len());
        assert_eq!(size, 452);
        let filter = Filter::delineate(&buffer).unwrap();
        assert_eq!(filter.len(), 452);
        assert_eq!(filter.num_ids(), 0);

        assert_eq!(filter.num_authors(), 2);
        let mut author_iter = filter.authors();
        assert_eq!(
            author_iter.next(),
            Some(
                Pubkey::read_hex(
                    b"e2ccf7cf20403f3f2a4a55b328f0de3be38558a7d5f33632fdaaefc726c1c8eb"
                )
                .unwrap()
            )
        );
        assert_eq!(
            author_iter.next(),
            Some(
                Pubkey::read_hex(
                    b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed"
                )
                .unwrap()
            )
        );
        assert_eq!(author_iter.next(), None);

        assert_eq!(filter.num_kinds(), 4);
        let mut kind_iter = filter.kinds();
        assert_eq!(kind_iter.next(), Some(Kind(1)));
        assert_eq!(kind_iter.next(), Some(Kind(5)));
        assert_eq!(kind_iter.next(), Some(Kind(9)));
        assert_eq!(kind_iter.next(), Some(Kind(30023)));
        assert_eq!(kind_iter.next(), None);

        assert_eq!(filter.limit(), u32::MAX);
        assert_eq!(filter.since(), Time(1681778790));
        assert_eq!(filter.until(), Time::max());

        let tags: Tags = filter.tags().unwrap();
        let mut tag_iter: TagsIter = tags.iter();
        let mut tag1_iter: TagsStringIter = tag_iter.next().unwrap();
        assert_eq!(tag1_iter.next(), Some(b"e".as_slice()));
        assert_eq!(
            tag1_iter.next(),
            Some(b"a9663055164ab8b30d9524656370c4bf93393bb051b7edf4556f40c5298dc0c7".as_slice())
        );
        assert_eq!(
            tag1_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(tag1_iter.next(), None);
        let mut tag2_iter = tag_iter.next().unwrap();
        assert_eq!(tag2_iter.next(), Some(b"p".as_slice()));
        assert_eq!(
            tag2_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(
            tag2_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(
            tag2_iter.next(),
            Some(b"2c86abcc98f7fd8a6750aab8df6c1863903f107206cc2d72e8afeb6c38357aed".as_slice())
        );
        assert_eq!(tag2_iter.next(), None);
        assert!(tag_iter.next().is_none());
    }
}
