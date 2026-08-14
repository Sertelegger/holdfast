//! `text_encoding` modes (spec §5.1, §5.2).
//!
//! Encoding is the last step of the pipeline, after ANSI stripping and
//! redaction, so `base64` with the default `redact: true` encodes the
//! *redacted* bytes. Byte-exact capture requires `redact: false`, which is
//! audit-logged.

use base64::Engine as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextEncoding {
    /// Lossy UTF-8: invalid sequences become U+FFFD (default).
    #[default]
    Utf8,
    /// Base64 of the processed byte stream.
    Base64,
    /// Lossy UTF-8 with non-printable bytes removed.
    LossyPrintable,
}

impl TextEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Base64 => "base64",
            Self::LossyPrintable => "lossy_printable",
        }
    }

    /// Parse a tool argument or resource query parameter.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "utf8" => Some(Self::Utf8),
            "base64" => Some(Self::Base64),
            "lossy_printable" => Some(Self::LossyPrintable),
            _ => None,
        }
    }

    /// The MIME type a resource fetch reports for this encoding (§5.5.3).
    pub fn mime_type(self) -> &'static str {
        match self {
            Self::Base64 => "application/octet-stream",
            _ => "text/plain; charset=utf-8",
        }
    }
}

/// Render processed bytes for the wire.
pub fn encode(bytes: &[u8], encoding: TextEncoding) -> String {
    match encoding {
        TextEncoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        TextEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
        TextEncoding::LossyPrintable => {
            // Drop C0 controls (except the layout bytes) and DEL first, so
            // they disappear rather than surviving a lossy decode. What is
            // left is decoded lossily, so invalid UTF-8 still becomes
            // U+FFFD instead of vanishing silently.
            let kept: Vec<u8> = bytes
                .iter()
                .copied()
                .filter(|b| matches!(b, b'\t' | b'\n' | b'\r') || (*b >= 0x20 && *b != 0x7f))
                .collect();
            String::from_utf8_lossy(&kept).into_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `é` — two bytes, both above 0x7f, neither valid alone.
    const E_ACUTE: &[u8] = &[0xc3, 0xa9];

    #[test]
    fn utf8_replaces_invalid_bytes_and_keeps_valid_text() {
        let out = encode(b"ok \xff done", TextEncoding::Utf8);
        assert_eq!(out, "ok \u{fffd} done");
    }

    /// The separator for the assertion above: "replaces invalid bytes" is
    /// also satisfied by an implementation that maps every non-ASCII byte
    /// to U+FFFD one at a time, which passes the whole rest of this module
    /// — including the §11.2 fixture, whose three bytes are `\xff`, a NUL
    /// and `\x80`, none of which is part of a valid multi-byte sequence.
    /// A *valid* two-byte sequence is the only input that tells a real
    /// UTF-8 decode apart from a per-byte one.
    #[test]
    fn utf8_decodes_multi_byte_sequences_rather_than_byte_by_byte() {
        let mut raw = b"caf".to_vec();
        raw.extend_from_slice(E_ACUTE);
        raw.extend_from_slice(b" \xff");
        assert_eq!(
            encode(&raw, TextEncoding::Utf8),
            "café \u{fffd}",
            "a valid two-byte sequence is one character, not two replacements"
        );
    }

    #[test]
    fn base64_round_trips_the_exact_bytes() {
        let raw: &[u8] = &[0xff, 0x00, 0x80, b'h', b'i'];
        let encoded = encode(raw, TextEncoding::Base64);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .unwrap();
        assert_eq!(decoded, raw, "base64 must be byte-exact for its input");
    }

    #[test]
    fn lossy_printable_strips_non_printables_and_keeps_the_text() {
        let out = encode(b"a\x00b\x07c\x7fd", TextEncoding::LossyPrintable);
        assert_eq!(out, "abcd");
    }

    #[test]
    fn lossy_printable_keeps_layout() {
        let out = encode(b"one\r\n\ttwo", TextEncoding::LossyPrintable);
        assert_eq!(out, "one\r\n\ttwo");
    }

    /// The other half of `lossy_printable`: the byte filter runs first,
    /// then a *lossy decode*. A filter that also dropped everything above
    /// 0x7f would satisfy every other assertion here — `\xff` and `\x80`
    /// vanishing looks the same as `\xff` and `\x80` becoming U+FFFD until
    /// a byte pair that decodes is put through it.
    #[test]
    fn lossy_printable_keeps_valid_multi_byte_text_and_replaces_invalid_bytes() {
        let mut raw = b"caf".to_vec();
        raw.extend_from_slice(E_ACUTE);
        raw.extend_from_slice(b"\x07\xff");
        assert_eq!(
            encode(&raw, TextEncoding::LossyPrintable),
            "café\u{fffd}",
            "the BEL is filtered out; the invalid byte survives as a replacement"
        );
    }

    #[test]
    fn the_spec_fixture_bytes_behave_as_documented() {
        // §11.2: `printf '\xff\x00\x80'` under each mode.
        let raw: &[u8] = &[0xff, 0x00, 0x80];
        assert_eq!(
            encode(raw, TextEncoding::Utf8),
            "\u{fffd}\u{0}\u{fffd}",
            "utf8 replaces the invalid bytes but a NUL is valid UTF-8 and survives"
        );
        assert_eq!(encode(raw, TextEncoding::Base64), "/wCA");
        assert_eq!(
            encode(raw, TextEncoding::LossyPrintable),
            "\u{fffd}\u{fffd}",
            "the NUL is gone; the two high bytes remain as replacements"
        );
    }

    #[test]
    fn parse_and_mime_types_agree_with_the_spec_table() {
        assert_eq!(TextEncoding::parse("utf8"), Some(TextEncoding::Utf8));
        assert_eq!(TextEncoding::parse("base64"), Some(TextEncoding::Base64));
        assert_eq!(
            TextEncoding::parse("lossy_printable"),
            Some(TextEncoding::LossyPrintable)
        );
        assert_eq!(TextEncoding::parse("utf-8"), None);
        assert_eq!(TextEncoding::Base64.mime_type(), "application/octet-stream");
        assert_eq!(TextEncoding::Utf8.mime_type(), "text/plain; charset=utf-8");
        assert_eq!(
            TextEncoding::LossyPrintable.mime_type(),
            "text/plain; charset=utf-8"
        );
    }

    /// `as_str` is the wire spelling — the name a response reports and the
    /// name `parse` has to accept back. Nothing else in the module reads
    /// it yet, so without this it is three unasserted arms: swapping two
    /// of them, or spelling `lossy_printable` with a hyphen, compiles and
    /// passes everything above.
    ///
    /// Both halves are here on purpose. The literals pin the spelling; the
    /// round-trip pins the pair, since a `parse`/`as_str` that agreed on a
    /// *wrong* spelling would round-trip perfectly.
    #[test]
    fn as_str_is_the_spelling_parse_accepts() {
        assert_eq!(TextEncoding::Utf8.as_str(), "utf8");
        assert_eq!(TextEncoding::Base64.as_str(), "base64");
        assert_eq!(TextEncoding::LossyPrintable.as_str(), "lossy_printable");
        for e in [
            TextEncoding::Utf8,
            TextEncoding::Base64,
            TextEncoding::LossyPrintable,
        ] {
            assert_eq!(TextEncoding::parse(e.as_str()), Some(e), "{e:?}");
        }
    }

    #[test]
    fn the_default_is_utf8() {
        assert_eq!(TextEncoding::default(), TextEncoding::Utf8);
    }
}
