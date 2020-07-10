// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub(crate) mod bufread;
pub(crate) mod crypter;
pub(crate) mod read;
pub(crate) mod write;

#[cfg_attr(docsrs, doc(cfg(feature = "io-async")))]
pub mod stream;

mod commonio;
