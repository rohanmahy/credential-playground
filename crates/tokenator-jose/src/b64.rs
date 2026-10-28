//! Unpadded base64url (RFC 7515 §2, RFC 4648 §5).

/// Why a base64url string did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B64Error {
    /// A byte outside the base64url alphabet, including `=` padding, `+`,
    /// `/`, and whitespace. `offset` is relative to the start of the
    /// encoded text.
    InvalidByte {
        /// Offset of the first offending byte.
        offset: usize,
    },
    /// The length is 1 more than a multiple of 4, which no byte string
    /// encodes to.
    InvalidLength,
    /// The last character has non-zero unused bits (a non-canonical
    /// encoding that strict decoders reject).
    NonCanonical,
}

impl core::fmt::Display for B64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            B64Error::InvalidByte { offset } => write!(f, "invalid base64url byte at {offset}"),
            B64Error::InvalidLength => f.write_str("invalid base64url length"),
            B64Error::NonCanonical => f.write_str("non-canonical base64url encoding"),
        }
    }
}

impl std::error::Error for B64Error {}

/// Encodes `bytes` as unpadded base64url.
///
/// ```
/// assert_eq!(tokenator_jose::b64u_encode(b"{\"alg\":\"none\"}"), "eyJhbGciOiJub25lIn0");
/// ```
pub fn b64u_encode(bytes: &[u8]) -> String {
    unimplemented!()
}

/// Strictly decodes unpadded base64url: no padding, no whitespace, no
/// standard-alphabet characters, canonical trailing bits.
///
/// ```
/// assert_eq!(tokenator_jose::b64u_decode("eyJhbGciOiJub25lIn0")?, b"{\"alg\":\"none\"}");
/// assert!(tokenator_jose::b64u_decode("eyJ=").is_err());
/// # Ok::<(), tokenator_jose::B64Error>(())
/// ```
pub fn b64u_decode(text: &str) -> Result<Vec<u8>, B64Error> {
    unimplemented!()
}
