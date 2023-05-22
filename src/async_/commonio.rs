// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::commonio::CommonOps;
use futures::ready;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, AsyncWrite, ReadBuf};

pub(crate) fn poll_read<R, Ops>(
    mut reader: Pin<&mut R>,
    cx: &mut Context<'_>,
    ops: &mut Ops,
    output: &mut ReadBuf<'_>,
) -> Poll<std::io::Result<()>>
where
    R: AsyncBufRead,
    Ops: CommonOps,
{
    loop {
        if ops.is_finalized() || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let eof;
        let (rd, wr) = {
            let input = ready!(reader.as_mut().poll_fill_buf(cx))?;
            eof = input.is_empty();
            ops.run(input, output.initialize_unfilled())?
        };
        reader.as_mut().consume(rd);
        output.advance(wr);

        if wr == 0 {
            if eof && !ops.is_finalized() {
                let wr = ops.finalize(output.initialize_unfilled())?;
                output.advance(wr);
            } else {
                continue;
            }
        } else {
            return Poll::Ready(Ok(()));
        }
    }
}

#[derive(Debug)]
pub(crate) struct AsyncBuffer {
    available: usize,
    buffer: Box<[u8]>,
    consumed: usize,
}

impl AsyncBuffer {
    pub fn new(capacity: usize) -> AsyncBuffer {
        AsyncBuffer {
            available: 0,
            buffer: vec![0u8; capacity].into_boxed_slice(),
            consumed: 0,
        }
    }

    pub fn poll_flush<W: AsyncWrite>(
        &mut self,
        mut writer: Pin<&mut W>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.available - self.consumed > 0 {
            let n = ready!(writer
                .as_mut()
                .poll_write(cx, &self.buffer[self.consumed..self.available]))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write the buffered data",
                )));
            } else {
                self.consumed += n;
            }
        }
        Poll::Ready(Ok(()))
    }
}
pub(crate) fn poll_write<W, Ops>(
    mut writer: Pin<&mut W>,
    cx: &mut Context<'_>,
    ops: &mut Ops,
    buffer: &mut AsyncBuffer,
    input: &[u8],
) -> Poll<std::io::Result<usize>>
where
    W: AsyncWrite,
    Ops: CommonOps,
{
    if input.is_empty() {
        return Poll::Ready(Ok(0));
    }

    // All buffered content needs to be flushed before writing because we give
    // the whole buffer to the crypter.
    ready!(buffer.poll_flush(writer.as_mut(), cx))?;

    loop {
        let (rd, wr) = ops.run(input, &mut buffer.buffer)?;
        buffer.available = wr;
        buffer.consumed = 0;
        if rd > 0 {
            return Poll::Ready(Ok(rd));
        } else {
            ready!(buffer.poll_flush(writer.as_mut(), cx))?;
        }
    }
}

pub(crate) fn poll_flush<W>(
    mut writer: Pin<&mut W>,
    cx: &mut Context<'_>,
    buffer: &mut AsyncBuffer,
) -> Poll<std::io::Result<()>>
where
    W: AsyncWrite,
{
    ready!(buffer.poll_flush(writer.as_mut(), cx))?;
    writer.poll_flush(cx)
}

pub(crate) fn poll_shutdown<W, Ops>(
    mut writer: Pin<&mut W>,
    cx: &mut Context<'_>,
    ops: &mut Ops,
    buffer: &mut AsyncBuffer,
) -> Poll<std::io::Result<()>>
where
    W: AsyncWrite,
    Ops: CommonOps,
{
    ready!(buffer.poll_flush(writer.as_mut(), cx))?;
    loop {
        let (_, wr) = ops.run(&[], &mut buffer.buffer)?;
        buffer.available = wr;
        buffer.consumed = 0;
        ready!(buffer.poll_flush(writer.as_mut(), cx))?;
        if wr == 0 {
            break;
        }
    }
    loop {
        let wr = ops.finalize(&mut buffer.buffer)?;
        buffer.available = wr;
        buffer.consumed = 0;
        ready!(buffer.poll_flush(writer.as_mut(), cx))?;
        if wr == 0 {
            break;
        }
    }
    ready!(writer.poll_shutdown(cx))?;
    Poll::Ready(Ok(()))
}
