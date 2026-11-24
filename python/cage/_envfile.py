"""What the Rust env-file loader does to a line, for the Python side to match."""

# The characters Rust's `str::trim` removes (Unicode White_Space). Python's
# `str.strip()` also removes U+001C to U+001F, which the broker keeps.
_RUST_WHITESPACE = (
    "\t\n\x0b\x0c\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)
