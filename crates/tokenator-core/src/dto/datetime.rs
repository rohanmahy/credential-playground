//! Date/time chit (SPEC §4.3).

use serde::{Deserialize, Serialize};

/// Input of [`Engine::datetime`](crate::Engine::datetime).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(optional_fields = nullable))]
pub struct DateTimeRequest {
    /// The value being edited.
    pub input: DateTimeInput,
    /// Clock for the relative string.
    #[serde(default)]
    pub now: Option<i64>,
    /// Local offset east of UTC in minutes (the platform knows the zone).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(as = "Option<i32>", optional))]
    pub local_offset_minutes: i32,
}

/// One field of the chit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DateTimeInput {
    /// Epoch seconds as decimal text, integer or fractional
    /// (`1363896240`, `1363896240.5`).
    Epoch {
        /// The text.
        text: String,
    },
    /// Epoch milliseconds.
    Millis {
        /// Milliseconds.
        millis: i64,
    },
    /// RFC 3339 `date-time`, any offset.
    Rfc3339 {
        /// The text.
        text: String,
    },
    /// RFC 3339 `full-date` (tag 1004).
    Date {
        /// The text.
        text: String,
    },
    /// Days since 1970-01-01 (tag 100).
    Days {
        /// Days.
        days: i64,
    },
    /// EDN of a time item (`1(1363896240)`, `dt'…'`, `0("…")`, …).
    Edn {
        /// The text.
        text: String,
    },
    /// Hex of a CBOR time item.
    CborHex {
        /// The hex.
        hex: String,
    },
}

/// Every representation, in sync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct DateTimeForms {
    /// Epoch seconds as decimal text (fraction only when non-zero).
    pub epoch: String,
    /// Epoch milliseconds (floor).
    pub millis: i64,
    /// RFC 3339 in UTC (`Z`).
    pub rfc3339_utc: String,
    /// RFC 3339 at `local_offset_minutes` (`+02:00`; `+00:00` for 0).
    pub rfc3339_local: String,
    /// The offset used.
    pub local_offset_minutes: i32,
    /// `"in 3 h 12 m"`, `"2 d ago"`, `"now"`; `None` without `now`.
    pub relative: Option<String>,
    /// The CBOR forms in `tokenator_edn::datetime::DateForm::ALL` order.
    pub forms: Vec<DateTimeFormView>,
}

/// One CBOR form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct DateTimeFormView {
    /// Which form.
    pub form: DateFormKind,
    /// Compact EDN.
    pub edn: String,
    /// Preferred-serialization CBOR, lowercase hex.
    pub cbor_hex: String,
}

/// The CBOR forms of `tokenator_edn::datetime::DateForm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum DateFormKind {
    /// Bare epoch seconds.
    Epoch,
    /// `1(epoch)`.
    Tag1,
    /// Bare RFC 3339 text.
    Rfc3339,
    /// `0("…")`.
    Tag0,
    /// `100(days)`.
    Tag100,
    /// `1004("YYYY-MM-DD")`.
    Tag1004,
    /// `dt'…'`.
    Dt,
    /// `DT'…'`.
    DtTagged,
}
