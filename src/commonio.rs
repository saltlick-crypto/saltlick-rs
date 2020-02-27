// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    crypter::{Decrypter, Encrypter},
    SaltlickError,
};
use std::io::{self, BufRead, Write};

pub(crate) trait CommonOps {
    fn run(&mut self, input: &[u8], output: &mut [u8]) -> io::Result<(usize, usize)>;

    fn finalize(&mut self, output: &mut [u8]) -> io::Result<usize>;

    fn is_finalized(&self) -> bool;
}

impl CommonOps for Decrypter {
    fn run(&mut self, input: &[u8], output: &mut [u8]) -> io::Result<(usize, usize)> {
        Ok(self.update(input, output)?)
    }

    fn finalize(&mut self, _output: &mut [u8]) -> io::Result<usize> {
        if self.is_not_finalized() {
            Err(SaltlickError::Incomplete.into())
        } else {
            Ok(0)
        }
    }

    fn is_finalized(&self) -> bool {
        self.is_finalized()
    }
}

impl CommonOps for Encrypter {
    fn run(&mut self, input: &[u8], output: &mut [u8]) -> io::Result<(usize, usize)> {
        Ok(self.update(input, output, false)?)
    }

    fn finalize(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let (_, wr) = self.update(&[], output, true)?;
        Ok(wr)
    }

    fn is_finalized(&self) -> bool {
        self.is_finalized()
    }
}

pub(crate) fn read<R, Ops>(reader: &mut R, ops: &mut Ops, output: &mut [u8]) -> io::Result<usize>
where
    R: BufRead,
    Ops: CommonOps,
{
    let mut nwritten = 0;
    loop {
        if ops.is_finalized() || nwritten >= output.len() {
            return Ok(nwritten);
        }

        let eof;
        let (rd, wr) = {
            let input = reader.fill_buf()?;
            eof = input.is_empty();
            ops.run(input, &mut output[nwritten..])?
        };
        reader.consume(rd);
        nwritten += wr;

        if wr == 0 {
            if eof && !ops.is_finalized() {
                nwritten += ops.finalize(&mut output[nwritten..])?;
            } else {
                continue;
            }
        } else {
            return Ok(nwritten);
        }
    }
}

#[derive(Debug)]
pub(crate) struct Buffer {
    available: usize,
    buffer: Box<[u8]>,
    consumed: usize,
    panicked: bool,
}

impl Buffer {
    pub fn new(capacity: usize) -> Buffer {
        Buffer {
            available: 0,
            buffer: vec![0u8; capacity].into_boxed_slice(),
            consumed: 0,
            panicked: false,
        }
    }

    pub fn flush<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        while self.available - self.consumed > 0 {
            self.panicked = true;
            let res = writer.write(&self.buffer[self.consumed..self.available]);
            self.panicked = false;
            match res {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write the buffered data",
                    ));
                }
                Ok(n) => self.consumed += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn panicked(&self) -> bool {
        self.panicked
    }
}

pub(crate) fn write<W, Ops>(
    writer: &mut W,
    ops: &mut Ops,
    buffer: &mut Buffer,
    input: &[u8],
) -> io::Result<usize>
where
    W: Write,
    Ops: CommonOps,
{
    // All buffered content needs to be flushed before writing because we give
    // the whole buffer to the crypter.
    buffer.flush(writer)?;

    // Returning a zero write is an error, so keep updating until we read
    // some input or error.
    let mut last_rd = 0;
    while last_rd == 0 {
        let (rd, wr) = ops.run(input, &mut buffer.buffer)?;
        buffer.available = wr;
        buffer.consumed = 0;
        last_rd = rd;
        buffer.flush(writer)?;
    }
    Ok(last_rd)
}

pub(crate) fn write_finalized<W, Ops>(
    writer: &mut W,
    ops: &mut Ops,
    buffer: &mut Buffer,
) -> io::Result<()>
where
    W: Write,
    Ops: CommonOps,
{
    buffer.flush(writer)?;
    loop {
        let (_, wr) = ops.run(&[], &mut buffer.buffer)?;
        buffer.available = wr;
        buffer.consumed = 0;
        buffer.flush(writer)?;
        if wr == 0 {
            break;
        }
    }
    loop {
        let wr = ops.finalize(&mut buffer.buffer)?;
        buffer.available = wr;
        buffer.consumed = 0;
        buffer.flush(writer)?;
        if wr == 0 {
            break;
        }
    }
    writer.flush()?;
    Ok(())
}
