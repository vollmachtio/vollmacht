use crate::Error;

pub const MAX_BODY: usize = 65_536;

/// Incremental, bounded single-frame decoder. `finish` means the caller saw EOF.
/// Errors poison the decoder, preventing recovery from ignored malformed input.
#[derive(Default)]
pub struct FrameDecoder {
    prefix: [u8; 4],
    prefix_len: usize,
    expected: Option<usize>,
    body: Vec<u8>,
    failed: bool,
}

impl FrameDecoder {
    pub fn feed(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Protocol);
        }
        if self.prefix_len < 4 {
            let count = bytes.len().min(4 - self.prefix_len);
            self.prefix[self.prefix_len..self.prefix_len + count].copy_from_slice(&bytes[..count]);
            self.prefix_len += count;
            bytes = &bytes[count..];
            if self.prefix_len < 4 {
                return Ok(());
            }
            let size = u32::from_be_bytes(self.prefix) as usize;
            if !(1..=MAX_BODY).contains(&size) {
                self.failed = true;
                return Err(Error::Protocol);
            }
            self.expected = Some(size);
        }
        let remaining = self.expected.unwrap_or(0) - self.body.len();
        if bytes.len() > remaining {
            self.failed = true;
            return Err(Error::Protocol);
        }
        self.body.extend_from_slice(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.failed || self.expected != Some(self.body.len()) {
            return Err(Error::Protocol);
        }
        Ok(self.body)
    }
}

pub fn frame(body: &[u8]) -> Result<Vec<u8>, Error> {
    if !(1..=MAX_BODY).contains(&body.len()) {
        return Err(Error::Protocol);
    }
    let mut output = Vec::with_capacity(4 + body.len());
    output.extend_from_slice(&(body.len() as u32).to_be_bytes());
    output.extend_from_slice(body);
    Ok(output)
}
