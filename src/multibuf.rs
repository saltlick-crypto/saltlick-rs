// Copyright (c) 2019, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cmp;
use std::iter::FromIterator;

use bytes::{Buf, Bytes};

/// Non-contiguous [`bytes::Buf`] implementation over a collection of byte
/// buffers.
///
/// Provides a way to return multiple sequential buffers without immediately
/// performing a memory copy. The trade-off is that it is not possible to seek
/// or rewind in the stream of data.
///
/// [`bytes::Buf`]: https://docs.rs/bytes/latest/bytes/trait.Buf.html
///
/// # Example
///
/// ```
/// use saltlick::crypter::{MultiBuf, Buf};
///
/// // Existing buffers can be pushed onto the MultiBuf - no reallocation of
/// // the buffers occurs.
/// let mut multibuf = MultiBuf::new();
/// multibuf.push(vec![1, 2, 3]);
/// multibuf.push(vec![4, 5, 6]);
///
/// // One MultiBuf can extend another MultiBuf - this also does not result in
/// // any reallocation of underlying buffers.
/// let mut multibuf2 = MultiBuf::new();
/// multibuf2.push(vec![7, 8, 9]);
/// multibuf.extend(multibuf2);
///
/// // Data is accessible through all `Buf` interfaces.
/// let expected = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
/// let actual = multibuf.into_vec();
/// assert_eq!(expected, actual);
/// ```
#[derive(Clone, Debug, Default)]
pub struct MultiBuf {
    buffers: Vec<Bytes>,
}

impl MultiBuf {
    /// Creates a new, empty MultiBuf.
    pub fn new() -> MultiBuf {
        MultiBuf {
            buffers: Vec::new(),
        }
    }

    /// Pushes a new buffer to the end of the MultiBuf.
    pub fn push(&mut self, buf: impl Into<Bytes>) {
        self.buffers.push(buf.into());
    }

    /// Appends the contents of `other` to this MultiBuf, consuming `other`.
    pub fn extend(&mut self, other: MultiBuf) {
        self.buffers.extend(other.buffers);
    }

    /// Copies remaining bytes into a new `Vec`.
    pub fn into_vec(mut self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl Buf for MultiBuf {
    fn remaining(&self) -> usize {
        self.buffers.iter().map(Buf::remaining).sum()
    }

    fn bytes(&self) -> &[u8] {
        match self.buffers.get(0) {
            Some(ref buf) if buf.has_remaining() => buf.bytes(),
            _ => &[],
        }
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining());
        let mut remaining_cnt = cnt;
        loop {
            let buf = &mut self.buffers[0];
            let n = cmp::min(buf.remaining(), remaining_cnt);
            buf.advance(n);
            remaining_cnt -= n;
            if !buf.has_remaining() {
                self.buffers.remove(0);
            }
            if remaining_cnt == 0 {
                break;
            }
        }
    }

    fn to_bytes(&mut self) -> Bytes {
        self.buffers
            .iter()
            .map(Buf::bytes)
            .fold(Vec::with_capacity(self.remaining()), |mut acc, bs| {
                acc.extend(bs);
                acc
            })
            .into()
    }
}

impl<A> FromIterator<A> for MultiBuf
where
    A: Into<Bytes>,
{
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = A>,
    {
        let buffers = iter.into_iter().map(A::into).map(Bytes::into).collect();
        MultiBuf { buffers }
    }
}

impl IntoIterator for MultiBuf {
    type Item = Bytes;
    type IntoIter = ::std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.buffers.into_iter().collect::<Vec<_>>().into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::MultiBuf;
    use bytes::Buf;

    #[test]
    fn empty_test() {
        let buf = MultiBuf::new();
        assert_eq!(0, buf.remaining());
        assert_eq!(&[] as &[u8], buf.bytes());
        assert_eq!(Vec::<u8>::new(), buf.into_vec());
    }

    #[test]
    fn multiple_empty_test() {
        let mut buf = MultiBuf::new();
        buf.push(&[] as &[u8]);
        buf.push(&[] as &[u8]);
        buf.push(&[] as &[u8]);
        assert_eq!(0, buf.remaining());
        assert_eq!(&[] as &[u8], buf.bytes());
        assert_eq!(Vec::<u8>::new(), buf.into_vec());
    }

    #[test]
    fn multiple_chunk_test() {
        let buf: MultiBuf = vec![vec![0u8, 1, 2], vec![3], vec![4, 5], vec![], vec![6, 7, 8]]
            .into_iter()
            .collect();
        assert_eq!(9, buf.remaining());
        assert_eq!(&[0u8, 1, 2] as &[u8], buf.bytes());
        assert_eq!(vec![0, 1, 2, 3, 4, 5, 6, 7, 8], buf.into_vec());
    }

    #[test]
    fn read_write_read_test() {
        let mut buf: MultiBuf = vec![vec![0u8, 1, 2], vec![3]].into_iter().collect();
        let buf2: MultiBuf = vec![vec![4, 5], vec![], vec![6, 7, 8]]
            .into_iter()
            .collect();
        assert_eq!(4, buf.remaining());
        assert_eq!(&[0u8, 1, 2] as &[u8], buf.bytes());
        buf.advance(3);
        assert_eq!(1, buf.remaining());
        assert_eq!(&[3u8] as &[u8], buf.bytes());
        buf.extend(buf2);
        assert_eq!(6, buf.remaining());
        assert_eq!(&[3u8] as &[u8], buf.bytes());
        buf.advance(2);
        assert_eq!(4, buf.remaining());
        assert_eq!(&[5u8] as &[u8], buf.bytes());
        assert_eq!(vec![5, 6, 7, 8], buf.into_vec());
    }

    #[test]
    #[should_panic]
    fn advance_beyond_end_panic_test() {
        let mut buf = MultiBuf::new();
        buf.advance(1);
    }
}
