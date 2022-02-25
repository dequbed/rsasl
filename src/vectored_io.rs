use std::io;
use std::io::{IoSlice, Write};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// An adapter that allows to more comfortable write using scatter-gather IO by handing the
/// IoSlice lifecycle
pub struct VectoredWriter<'io, const N: usize> {
    /// The number of bufs to skip when resuming an interrupted write.
    skip: usize,
    data: [&'io [u8]; N],
}

impl<'io, const N: usize> VectoredWriter<'io, N> {
    pub fn new(data: [&'io [u8]; N]) -> Self {
        Self { skip: 0, data }
    }

    pub fn is_done(&self) -> bool {
        self.skip >= N
    }

    pub fn write_vectored_inner(
        &mut self,
        bufs: &mut [IoSlice<'io>; N],
        writer: &mut impl Write,
    ) -> io::Result<usize> {
        if self.skip >= N {
            return Ok(0);
        }
        let len = writer.write_vectored(&bufs[self.skip..])?;

        // Number of buffers to remove.
        let mut remove = 0;
        // Total length of all the to be removed buffers.
        let mut accumulated_len = 0;
        for buf in self.data[self.skip..].iter() {
            if accumulated_len + buf.len() > len {
                break;
            } else {
                accumulated_len += buf.len();
                remove += 1;
            }
        }
        self.skip += remove;
        if self.skip < N {
            let rem = len - accumulated_len;
            self.data[self.skip] = &self.data[self.skip][rem..];
            bufs[self.skip] = IoSlice::new(&self.data[self.skip]);
        }

        Ok(len)
    }

    pub fn write_all_vectored(&mut self, mut writer: impl Write) -> io::Result<usize> {
        if self.skip >= N {
            return Ok(0);
        }

        let mut bufs: [IoSlice; N] = self.data.map(IoSlice::new);

        let mut written = 0;
        while {
            written += self.write_vectored_inner(&mut bufs, &mut writer)?;
            self.skip < N
        } {}

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_with_split_writer() {
        // Split writer will at most write `reset` bytes per call to write()
        struct SplitWriter {
            data: Cursor<Vec<u8>>,
            cnt: usize,
            reset: usize,
        }
        impl Write for SplitWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let wrt = if self.cnt != 0 && self.cnt < buf.len() {
                    println!("Partial write: {:?}", &buf[0..self.cnt]);
                    self.data.write(&buf[0..self.cnt])?
                } else {
                    println!("Complete write: {:?}", &buf[..]);
                    self.data.write(buf)?
                };
                self.cnt = self.cnt.saturating_sub(wrt);
                if self.cnt == 0 {
                    self.cnt = self.reset;
                }
                Ok(wrt)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.data.flush()
            }
        }

        let data: [&[u8]; 4] = [b"dead", b"beef", b"cafe", b"babe"];

        let mut out = SplitWriter {
            data: Cursor::new(Vec::with_capacity(16)),
            cnt: 5,
            reset: 5,
        };

        println!("Preparing to write {:?}", data);

        let mut vecw = VectoredWriter::new(data);
        println!("{:?}", vecw);
        let n = vecw.write_all_vectored(&mut out).unwrap();

        assert_eq!(n, 16);
        assert_eq!(&out.data.into_inner()[..], b"deadbeefcafebabe");
    }
}
