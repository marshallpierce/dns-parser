# Next

- `Name` no longer assumes that labels are all ASCII, or text at all, since the DNS spec doesn't require it either.
    - Notably, this allows parsing UTF-8 labels as used in mDNS.
    - Unfortunately, this means that several types can no longer implement `ToString`, as there isn't an infallible
      canonical text representation.
    - `StrName` is provided for the common case of UTF-8 labels
- Update MSRV to 1.80.0 to allow `slice::split_at_checked`. This is older than rustc in Debian Stable (trixie, 1.85.0),
  though newer than Ubuntu LTS (Noble Numbat, 1.75.0).
- Small syntactic tweaks to address all compiler and clippy warnings

# 0.8.0

Current version when changelog started