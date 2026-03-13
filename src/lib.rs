#![recursion_limit = "100"]
//! The network-agnostic DNS parser library
//!
//! [Documentation](https://docs.rs/dns-parser) |
//! [Github](https://github.com/tailhook/dns-parser) |
//! [Crate](https://crates.io/crates/dns-parser)
//!
//! Use [`Builder`] to create a new outgoing packet.
//!
//! Use [`Packet::parse`] to parse a packet into a data structure.
//!
//! [`Builder`]: struct.Builder.html
//! [`Packet::parse`]: struct.Packet.html#method.parse
//!
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

extern crate byteorder;
#[cfg(test)]
#[macro_use]
extern crate matches;
#[macro_use(quick_error)]
extern crate quick_error;
#[cfg(feature = "with-serde")]
#[macro_use]
extern crate serde_derive;
#[cfg(test)]
extern crate itertools;

mod builder;
mod enums;
mod error;
mod header;
mod name;
mod parser;
mod structs;

pub mod rdata;

pub use builder::Builder;
pub use enums::{Class, Opcode, QueryClass, QueryType, ResponseCode, Type};
pub use error::Error;
pub use header::Header;
pub use name::Name;
pub use rdata::RData;
pub use structs::{Packet, Question, ResourceRecord};
