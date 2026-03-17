use std::fmt;
use std::str::from_utf8;

use Error;

/// The DNS name as stored in the original packet
///
/// This contains just a reference to a slice that contains the data.
///
/// Since DNS names or labels do not specify any constraints on their contents other than lengths,
/// labels are just byte slices (`&[u8]`). In typical Internet usage, they are ASCII text, while in
/// mDNS, they are UTF-8.
///
/// It is preferable to iterate over labels (see [`Self::iter_labels`]) rather than splitting on
/// `.` in the dot-separated string form, since it is possible for DNS labels to themselves contain
/// a `.`.
#[derive(Clone, Copy)]
pub struct Name<'a> {
    /// Starting point for parsing a valid name.
    ///
    /// All labels starting from here must parse successfully.
    ///
    /// This contains only the data read before jumping elsewhere in `original` to follow a pointer.
    labels: &'a [u8],
    /// This is the original buffer size. The compressed names referred to in `labels` are relative
    /// to this.
    original: &'a [u8],
    /// True iff all labels can be parsed and are UTF-8
    all_labels_utf8: bool,
}

impl<'a> Name<'a> {
    /// Scan the data to get Name object
    ///
    /// The `data` should be a part of `original` where name should start.
    /// The `original` is the data starting at the start of a packet, so
    /// that offsets in compressed name starts from the `original`.
    pub fn scan(data: &'a [u8], original: &'a [u8]) -> Result<Name<'a>, Error> {
        let mut iter = LabelIter::new(data, original);
        // We need to parse at least to the first pointer to know how much of `data` was consumed.
        // However, we might as well parse everything so we can check if all labels are UTF-8.
        // The `.by_ref()` allows us to iterate, and advance the length counter, without consuming
        // the iterator.
        let all_labels_utf8 = iter.by_ref().try_fold(true, |all_previous_utf8, r| {
            r.map(|bytes| from_utf8(bytes).is_ok() && all_previous_utf8)
        })?;

        Ok(Self {
            labels: data
                .get(..iter.orig_name_len())
                .ok_or(Error::UnexpectedEOF)?,
            original,
            all_labels_utf8,
        })
    }

    /// Number of bytes serialized name occupies, not counting any bytes after reading the first
    /// pointer
    pub fn byte_len(&self) -> usize {
        self.labels.len()
    }

    /// Iterate over the labels in the name
    pub fn iter_labels(&self) -> impl Iterator<Item = &'a [u8]> {
        LabelIter::new(self.labels, self.original)
            // Name's contract guarantees that all labels can be parsed
            .filter_map(|r| r.ok())
    }

    /// If all labels are UTF-8, returns a `StrName` that provides access to `&str` labels
    pub fn as_str_name(&self) -> Option<StrName<'a>> {
        if self.all_labels_utf8 {
            Some(StrName { name: *self })
        } else {
            None
        }
    }
}

impl<'a> fmt::Debug for Name<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Name(")?;

        for (index, label_bytes) in self.iter_labels().enumerate() {
            if index != 0 {
                write!(fmt, ".")?;
            }
            match from_utf8(label_bytes) {
                Ok(l) => {
                    write!(fmt, "{}", l)?;
                }
                Err(_e) => {
                    write!(fmt, "<0x{}>", hex::encode(label_bytes))?;
                }
            }
        }

        write!(fmt, ")")
    }
}

/// A [`Name`] whose labels are all UTF-8.
///
/// The [`fmt::Display`] implementation produces the typical dot-separated text form of a DNS name,
/// though no escaping of any `.` characters that may exist in a label is performed (which is
/// possible, if unusual).
///
/// For precise label by label access, see [`Self::iter_labels`].
#[derive(Clone, Copy)]
pub struct StrName<'a> {
    /// All labels must already have been checked to be UTF-8.
    name: Name<'a>,
}

impl<'a> StrName<'a> {
    /// Iterate over the labels in the name, all of which are UTF-8
    pub fn iter_labels(&self) -> impl Iterator<Item = &'a str> {
        self.name
            .iter_labels()
            // all labels are UTF-8, so this won't drop anything
            .filter_map(|bytes| from_utf8(bytes).ok())
    }
}

impl<'a> fmt::Debug for StrName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StrName({})", self)
    }
}

impl<'a> fmt::Display for StrName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, l) in self.iter_labels().enumerate() {
            if index != 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", l)?;
        }
        Ok(())
    }
}

/// An iterator over labels in a [`Name`].
///
/// Stops iterating (produces `None`) at the end of the name, or once an error has been encountered.
///
/// See <https://www.rfc-editor.org/rfc/rfc1035.html> and <https://www.rfc-editor.org/rfc/rfc9267.html>
struct LabelIter<'a> {
    /// The next name bytes to read labels from
    remaining: &'a [u8],
    /// The complete DNS packet, which offsets in compressed labels are relative to
    original: &'a [u8],
    /// The last offset jumped to.
    ///
    /// Since we don't know where a name starts in the RR, we can't do exactly the anti-cycle
    /// check laid out in RFC 9267. However, we can still keep track of the _first_ pointer, and
    /// only allow the offset to decrease from there.
    last_offset: Option<usize>,
    /// True when we've reached the end, or encountered an error
    done: bool,
    /// Number of encoded bytes read when decoding the name. If it exceeds 255, it's an error per
    /// RFC 1035 2.3.4.
    ///
    /// It's not entirely clear what 4.1.4, which expands upon this, means by using the length of
    /// the compressed name. If multiple pointers are followed, for instance, when do we stop
    /// counting bytes towards the 255 limit?
    ///
    /// RFC 9267 suggests limiting to 255 bytes, including the decompressed size. So, we just count
    /// _all_ bytes read, including pointers, to be safe.
    encoded_name_len_read: usize,
    /// The number of bytes read from the original name data, after reading the first pointer.
    orig_name_len: Option<usize>,
}

impl<'a> LabelIter<'a> {
    const COMPRESSED_MARKER: u8 = 0xc0;

    /// See <https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4>
    const MAX_NAME_LEN: usize = 255;

    fn new(name: &'a [u8], original: &'a [u8]) -> Self {
        Self {
            remaining: name,
            original,
            last_offset: None,
            done: false,
            encoded_name_len_read: 0,
            orig_name_len: None,
        }
    }

    /// Read the next label in the name.
    ///
    /// Returns `None` if no labels are left.
    fn read_label(&mut self) -> Result<Option<&'a [u8]>, Error> {
        loop {
            let byte = self.read_byte()?;

            // Check for pointer per RFC 9267 Fig 2
            if byte & Self::COMPRESSED_MARKER == Self::COMPRESSED_MARKER {
                let target_offset =
                    u16::from_be_bytes([byte & !Self::COMPRESSED_MARKER, self.read_byte()?]).into();

                // This allows one forward jump since we don't know the name's position in the packet,
                // but this still prevents loops since all jumps must go backwards from there.
                let pointer_valid = match self.last_offset {
                    Some(o) => target_offset < o,
                    None => {
                        // record what we've previously read in the original name
                        self.orig_name_len = Some(self.encoded_name_len_read);
                        true
                    }
                };
                if !pointer_valid {
                    return Err(Error::BadPointer);
                }
                self.last_offset = Some(target_offset);

                self.remaining = self
                    .original
                    .get(target_offset..)
                    .ok_or(Error::UnexpectedEOF)?;
            } else if byte == 0 {
                return Ok(None);
            } else if byte < 64 {
                let len = byte.into();
                self.mark_bytes_read(len)?;
                let (label, rem) = self
                    .remaining
                    .split_at_checked(len)
                    .ok_or(Error::UnexpectedEOF)?;
                self.remaining = rem;
                return Ok(Some(label));
            } else {
                // Nonzero bit patterns in the top 2 bits except for 0xC0 above are invalid
                return Err(Error::UnknownLabelFormat);
            }
        }
    }

    /// Read the next byte from `self.name`
    fn read_byte(&mut self) -> Result<u8, Error> {
        self.mark_bytes_read(1)?;

        let (first, rem) = self.remaining.split_first().ok_or(Error::UnexpectedEOF)?;
        self.remaining = rem;
        Ok(*first)
    }

    /// Returns an error if `len` would push the total bytes read over the name length limit.
    ///
    /// Otherwise, records the new total length including `len`.
    fn mark_bytes_read(&mut self, len: usize) -> Result<(), Error> {
        let sum = self
            .encoded_name_len_read
            .checked_add(len)
            .ok_or(Error::InvalidNameLen)?;
        if sum > Self::MAX_NAME_LEN {
            Err(Error::InvalidNameLen)
        } else {
            self.encoded_name_len_read = sum;
            Ok(())
        }
    }

    /// Returns the number of bytes read from the original name buffer, before following any
    /// pointers
    fn orig_name_len(&self) -> usize {
        // if we didn't hit a pointer, the overall encoded length read is the number we want
        self.orig_name_len.unwrap_or(self.encoded_name_len_read)
    }
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = Result<&'a [u8], Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match self.read_label() {
            Ok(Some(l)) => Some(Ok(l)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use name::LabelIter;
    use Error;
    use Name;

    #[test]
    fn parse_badpointer_same_offset() {
        // A buffer where an offset points to itself,
        // which is a bad compression pointer.
        let same_offset = vec![192, 2, 192, 2];
        assert_eq!(
            Error::BadPointer,
            Name::scan(&same_offset, &same_offset).unwrap_err()
        );
    }

    #[test]
    fn parse_badpointer_forward_offset() {
        // A buffer where the offsets points back to each other which causes
        // infinite recursion if never checked, a bad compression pointer.
        let forwards_offset = vec![192, 2, 192, 4, 192, 2];

        assert_eq!(
            Error::BadPointer,
            Name::scan(&forwards_offset, &forwards_offset).unwrap_err(),
        )
    }

    #[test]
    fn nested_names() {
        // A buffer where an offset points to itself, a bad compression pointer.
        let buf = b"\x02xx\x00\x02yy\xc0\x00\x02zz\xc0\x04";

        assert_eq!(
            Name::scan(&buf[..], buf)
                .unwrap()
                .as_str_name()
                .unwrap()
                .to_string(),
            "xx"
        );
        assert_eq!(Name::scan(&buf[..], buf).unwrap().labels, b"\x02xx\x00");
        assert_eq!(
            Name::scan(&buf[4..], buf)
                .unwrap()
                .as_str_name()
                .unwrap()
                .to_string(),
            "yy.xx"
        );
        assert_eq!(
            Name::scan(&buf[4..], buf).unwrap().labels,
            b"\x02yy\xc0\x00"
        );
        assert_eq!(
            Name::scan(&buf[9..], buf)
                .unwrap()
                .as_str_name()
                .unwrap()
                .to_string(),
            "zz.yy.xx"
        );
        assert_eq!(
            Name::scan(&buf[9..], buf).unwrap().labels,
            b"\x02zz\xc0\x04"
        );
    }

    #[test]
    fn name_all_utf8_labels_ok() {
        let bytes = b"\x03foo\x03bar\0";

        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();
        assert_eq!("Name(foo.bar)", format!("{name:?}"));

        let str_name = name.as_str_name().unwrap();

        assert_eq!("foo.bar", str_name.to_string());
        assert_eq!("StrName(foo.bar)", format!("{str_name:?}"));
    }

    #[test]
    fn name_all_valid_but_not_utf8_labels_ok_no_str_name() {
        let bytes = b"\x03foo\x03ba\xFF\0";

        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();
        assert_eq!("Name(foo.<0x6261ff>)", format!("{name:?}"));

        assert!(name.as_str_name().is_none());
    }

    #[test]
    fn name_not_all_valid_labels_err() {
        // pointer past EOF
        let bytes = b"\x03foo\xC0\xFF";

        assert_eq!(
            Error::UnexpectedEOF,
            Name::scan(&bytes[..], &bytes[..]).unwrap_err()
        );
    }

    #[test]
    fn iter_labels_invalid_label_type() {
        let name = b"\x02ok\xA0";

        assert_eq!(
            vec![Ok("ok"), Err(Error::UnknownLabelFormat)],
            iter_labels(&name[..], &name[..])
        );
    }

    #[test]
    fn iter_labels_binary_and_utf8_labels() {
        // 3-byte unicode snowman, then, 2 non-UTF-8 bytes
        let name = b"\x03\xE2\x98\x83\x02\xFF\xFF\x00";

        assert_eq!(
            vec![Ok("☃".as_bytes()), Ok(b"\xFF\xFF"),],
            LabelIter::new(name, name).collect_vec()
        );
    }

    #[test]
    fn iter_labels_label_len_eof_err() {
        // eof when reading the label itself
        let name = b"\x03foo\x04bar";

        assert_eq!(
            vec![Ok("foo"), Err(Error::UnexpectedEOF)],
            iter_labels(&name[..], &name[..])
        );
    }

    #[test]
    fn iter_labels_eof_reading_next_byte_err() {
        // read the trailing nul as part of the second label, so it'll fail when looking for what
        // should be the nul suffix
        let name = b"\x03foo\x04bar\x00";

        assert_eq!(
            vec![Ok("foo"), Ok("bar\x00"), Err(Error::UnexpectedEOF)],
            iter_labels(&name[..], &name[..])
        );
    }

    #[test]
    fn iter_labels_ptr_to_self_err() {
        let name = b"\x01a\xC0\x02";

        assert_eq!(
            vec![Ok("a"), Err(Error::BadPointer)],
            iter_labels(&name[..], &name[..])
        );
    }

    #[test]
    fn iter_labels_ptr_eof_err() {
        let name = b"\x01a\xC0\x0A";

        assert_eq!(
            vec![Ok("a"), Err(Error::UnexpectedEOF)],
            iter_labels(&name[..], &name[..])
        );
    }

    #[test]
    fn iter_labels_ptr_second_byte_eof_err() {
        let name = b"\x01a\xC0";

        assert_eq!(
            vec![Ok("a"), Err(Error::UnexpectedEOF)],
            iter_labels(&name[..], &name[..])
        );
    }

    #[test]
    fn iter_labels_forward_ptr_then_backwards_ok() {
        // jump from first ptr to second is ok, and so is the backwards ptr
        let name = b"\x02ok\x00\xC0\x06\xC0\x00";

        assert_eq!(vec![Ok("ok")], iter_labels(&name[..], &name[..]));
    }

    #[test]
    fn iter_labels_two_forward_ptrs_error() {
        // jump from first ptr to second is ok, but from second to third is not
        let name = b"\xC0\x02\xC0\x04\x02hi";

        assert_eq!(
            vec![Err(Error::BadPointer)],
            iter_labels(&name[..], &name[..]),
        );
    }

    #[test]
    fn iter_labels_max_len_error_long_labels_limit_at_nul_byte() {
        // too long because of nul byte:
        // 4 labels of 1 + 59 = 60, 1 chunk of 1 + 14, + nul = 256
        let mut name = vec![];
        name.push(59);
        name.extend_from_slice(&[b'a'; 59]);
        name.push(59);
        name.extend_from_slice(&[b'b'; 59]);
        name.push(59);
        name.extend_from_slice(&[b'c'; 59]);
        name.push(59);
        name.extend_from_slice(&[b'd'; 59]);
        name.push(14);
        name.extend_from_slice(&[b'e'; 14]);
        name.push(0);

        assert_eq!(256, name.len());
        assert_eq!(
            vec![
                Ok("a".repeat(59).as_str()),
                Ok("b".repeat(59).as_str()),
                Ok("c".repeat(59).as_str()),
                Ok("d".repeat(59).as_str()),
                Ok("e".repeat(14).as_str()),
                Err(Error::InvalidNameLen)
            ],
            iter_labels(&name, &name)
        );
    }

    #[test]
    fn iter_labels_max_len_error_long_labels() {
        // too long because of last label:
        // 4 labels of 1 + 59 = 60, 1 chunk of 1 + 15, + nul = 257
        let mut name = vec![];
        name.push(59);
        name.extend_from_slice(&[b'a'; 59]);
        name.push(59);
        name.extend_from_slice(&[b'b'; 59]);
        name.push(59);
        name.extend_from_slice(&[b'c'; 59]);
        name.push(59);
        name.extend_from_slice(&[b'd'; 59]);
        name.push(15);
        name.extend_from_slice(&[b'e'; 15]);
        name.push(0);

        assert_eq!(257, name.len());
        assert_eq!(
            vec![
                Ok("a".repeat(59).as_str()),
                Ok("b".repeat(59).as_str()),
                Ok("c".repeat(59).as_str()),
                Ok("d".repeat(59).as_str()),
                Err(Error::InvalidNameLen)
            ],
            iter_labels(&name, &name)
        );
    }

    #[test]
    fn iter_labels_max_len_error_recursive_pointers() {
        let mut name = b"\x04quux\x00".to_vec();
        // 125 pointers each going back by 2, totaling 250 bytes, plus the 6 byte prefix = 256
        for i in 0..=124 {
            name.push(0xC0);
            if i == 0 {
                name.push(0);
            } else {
                name.push(6 + (i - 1) * 2)
            }
        }
        assert_eq!(256, name.len());
        assert_eq!(
            vec![Ok("quux"), Err(Error::InvalidNameLen)],
            // start with last 2 bytes
            iter_labels(&name[254..], &name)
        );
    }

    #[test]
    fn iter_labels_max_len_ok_recursive_pointers() {
        let mut name = b"\x01a\x00".to_vec();
        // 126 pointers each going back by 2, totaling 252 bytes, plus the 3 byte prefix = 255
        for i in 0..=125 {
            name.push(0xC0);
            if i == 0 {
                name.push(0);
            } else {
                name.push(3 + (i - 1) * 2)
            }
        }
        assert_eq!(255, name.len());
        assert_eq!(
            vec![Ok("a")],
            // start with last 2 bytes
            iter_labels(&name[253..], &name)
        );
    }

    #[test]
    fn orig_name_parse_len_empty() {
        let bytes = b"\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();
        assert_eq!(1, name.labels.len());
    }

    #[test]
    fn orig_name_parse_len_no_pointers() {
        let bytes = b"\x03foo\x03bar\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();
        assert_eq!(9, name.labels.len());
    }

    #[test]
    fn orig_name_parse_len_starts_with_ptr() {
        let bytes = b"\x03baz\x00\xC0\x00";
        let name = Name::scan(&bytes[5..], &bytes[..]).unwrap();
        // just the pointer
        assert_eq!(2, name.labels.len());
    }

    #[test]
    fn orig_name_parse_len_stops_at_first_pointer_after_some_labels() {
        let bytes = b"\x03baz\x00\x03foo\x03bar\xC0\x00";
        let name = Name::scan(&bytes[5..], &bytes[..]).unwrap();
        // two labels plus the pointer
        assert_eq!(10, name.labels.len());
    }

    #[test]
    fn name_as_string_empty() {
        let bytes = b"\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();

        assert_eq!("", name.as_str_name().unwrap().to_string());
    }

    #[test]
    fn name_as_string_all_labels_text() {
        let bytes = b"\x03foo\x03bar\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();

        assert_eq!("foo.bar", name.as_str_name().unwrap().to_string());
    }

    #[test]
    fn name_as_string_some_labels_binary() {
        let bytes = b"\x03foo\x03\xFF\xFA\xF0\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();

        assert!(name.as_str_name().is_none());
    }

    #[test]
    fn name_debug_empty() {
        let bytes = b"\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();

        assert_eq!("Name()", format!("{name:?}"));
    }

    #[test]
    fn name_debug_all_labels_text() {
        let bytes = b"\x03foo\x03bar\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();

        assert_eq!("Name(foo.bar)", format!("{name:?}"));
        assert_eq!(
            "StrName(foo.bar)",
            format!("{:?}", name.as_str_name().unwrap())
        );
    }

    #[test]
    fn name_debug_some_labels_binary() {
        let bytes = b"\x03foo\x03\xFF\xFA\xF0\x00";
        let name = Name::scan(&bytes[..], &bytes[..]).unwrap();

        assert_eq!("Name(foo.<0xfffaf0>)", format!("{name:?}"));
    }

    fn iter_labels<'a>(name: &'a [u8], original: &'a [u8]) -> Vec<Result<&'a str, Error>> {
        LabelIter::new(name, original)
            .map(|r| r.map(|l| std::str::from_utf8(l).unwrap()))
            .collect_vec()
    }
}
