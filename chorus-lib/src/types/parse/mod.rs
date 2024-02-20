pub mod json_escape;

pub mod json_parse;

pub mod utf8;

#[inline]
pub fn put(output: &mut [u8], offset: usize, data: &[u8]) -> Result<(), crate::error::Error> {
    if output.len() < offset + data.len() {
        Err(crate::error::ChorusError::BufferTooSmall.into())
    } else {
        output[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }
}
