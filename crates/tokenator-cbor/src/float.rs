//! Bit-exact conversions between binary16, binary32, and binary64.
//!
//! Hardware conversions (and `as` casts) may quiet signaling NaNs, so all
//! conversions here work on bit patterns. Widening is always exact; narrowing
//! succeeds only when no bit of the value (or NaN payload) is lost.

use crate::FloatWidth;

const F64_MANT_BITS: u32 = 52;
const F64_MANT_MASK: u64 = (1 << F64_MANT_BITS) - 1;
const F64_EXP_MAX: u64 = 0x7ff;
const F64_BIAS: i32 = 1023;

/// Exponent and mantissa sizes of a narrower format.
#[derive(Clone, Copy)]
struct Format {
    exp_bits: u32,
    mant_bits: u32,
}

const F16: Format = Format {
    exp_bits: 5,
    mant_bits: 10,
};
const F32: Format = Format {
    exp_bits: 8,
    mant_bits: 23,
};

impl Format {
    fn bias(self) -> i32 {
        (1 << (self.exp_bits - 1)) - 1
    }

    fn exp_max(self) -> u64 {
        (1 << self.exp_bits) - 1
    }

    /// Mantissa bits dropped when narrowing from binary64.
    fn drop(self) -> u32 {
        F64_MANT_BITS - self.mant_bits
    }
}

/// Widens `bits` in format `fmt` to binary64 bits, exactly.
fn widen(bits: u64, fmt: Format) -> u64 {
    let sign = (bits >> (fmt.exp_bits + fmt.mant_bits)) & 1;
    let exp = (bits >> fmt.mant_bits) & fmt.exp_max();
    let mant = bits & ((1 << fmt.mant_bits) - 1);
    let sign = sign << 63;
    if exp == fmt.exp_max() {
        // Infinity or NaN: left-align the payload.
        return sign | (F64_EXP_MAX << F64_MANT_BITS) | (mant << fmt.drop());
    }
    if exp == 0 {
        if mant == 0 {
            return sign;
        }
        // Subnormal: normalize so the leading 1 becomes implicit.
        let top = 63 - mant.leading_zeros();
        let e = top as i32 + 1 - fmt.bias() - fmt.mant_bits as i32;
        let exp64 = (e + F64_BIAS) as u64;
        let mant64 = (mant << (F64_MANT_BITS - top)) & F64_MANT_MASK;
        return sign | (exp64 << F64_MANT_BITS) | mant64;
    }
    let e = exp as i32 - fmt.bias();
    let exp64 = (e + F64_BIAS) as u64;
    sign | (exp64 << F64_MANT_BITS) | (mant << fmt.drop())
}

/// Narrows binary64 `bits` to format `fmt`, or `None` if that loses bits.
fn narrow(bits: u64, fmt: Format) -> Option<u64> {
    let sign = (bits >> 63) << (fmt.exp_bits + fmt.mant_bits);
    let exp = (bits >> F64_MANT_BITS) & F64_EXP_MAX;
    let mant = bits & F64_MANT_MASK;
    let low_zero = |shift: u32| mant & ((1 << shift) - 1) == 0;
    if exp == F64_EXP_MAX {
        return low_zero(fmt.drop())
            .then(|| sign | (fmt.exp_max() << fmt.mant_bits) | (mant >> fmt.drop()));
    }
    if exp == 0 {
        // Zero, or a binary64 subnormal (far below any narrower format).
        return (mant == 0).then_some(sign);
    }
    let e = exp as i32 - F64_BIAS;
    if e > fmt.bias() {
        return None;
    }
    if e >= 1 - fmt.bias() {
        return low_zero(fmt.drop())
            .then(|| sign | (((e + fmt.bias()) as u64) << fmt.mant_bits) | (mant >> fmt.drop()));
    }
    // Subnormal in the narrower format.
    let min_e = 1 - fmt.bias() - fmt.mant_bits as i32;
    if e < min_e {
        return None;
    }
    let sig = mant | (1 << F64_MANT_BITS);
    let shift = fmt.drop() + (1 - fmt.bias() - e) as u32;
    (sig & ((1 << shift) - 1) == 0).then(|| sign | (sig >> shift))
}

/// binary16 bits to an `f64`.
pub(crate) fn from_f16(bits: u16) -> f64 {
    f64::from_bits(widen(u64::from(bits), F16))
}

/// binary32 bits to an `f64`.
pub(crate) fn from_f32(bits: u32) -> f64 {
    f64::from_bits(widen(u64::from(bits), F32))
}

/// `f` as binary16 bits, if exact.
pub(crate) fn to_f16(f: f64) -> Option<u16> {
    narrow(f.to_bits(), F16).and_then(|b| u16::try_from(b).ok())
}

/// `f` as binary32 bits, if exact.
pub(crate) fn to_f32(f: f64) -> Option<u32> {
    narrow(f.to_bits(), F32).and_then(|b| u32::try_from(b).ok())
}

/// The shortest width that represents `f` exactly.
pub(crate) fn shortest_width(f: f64) -> FloatWidth {
    if to_f16(f).is_some() {
        FloatWidth::F16
    } else if to_f32(f).is_some() {
        FloatWidth::F32
    } else {
        FloatWidth::F64
    }
}

/// Appends the encoding of `f` at `width`, or at the shortest exact width if
/// `width` cannot represent `f` exactly (which is then always wider).
pub(crate) fn write(out: &mut Vec<u8>, f: f64, width: FloatWidth) {
    match (effective_width(f, width), to_f16(f), to_f32(f)) {
        (FloatWidth::F16, Some(b), _) => {
            out.push(0xf9);
            out.extend_from_slice(&b.to_be_bytes());
        }
        (FloatWidth::F32, _, Some(b)) => {
            out.push(0xfa);
            out.extend_from_slice(&b.to_be_bytes());
        }
        _ => {
            out.push(0xfb);
            out.extend_from_slice(&f.to_bits().to_be_bytes());
        }
    }
}

/// The width [`write`] uses for `f` at `width`.
pub(crate) fn effective_width(f: f64, width: FloatWidth) -> FloatWidth {
    match width {
        FloatWidth::F16 if to_f16(f).is_some() => width,
        FloatWidth::F32 if to_f32(f).is_some() => width,
        FloatWidth::F64 => width,
        _ => shortest_width(f),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_f16_round_trips() {
        for b in 0..=u16::MAX {
            assert_eq!(to_f16(from_f16(b)), Some(b), "{b:#06x}");
        }
    }

    #[test]
    fn f16_matches_native_f32_for_non_nan() {
        for b in 0..=u16::MAX {
            let f = from_f16(b);
            if !f.is_nan() {
                let f32_bits = to_f32(f).unwrap();
                assert_eq!(f64::from(f32::from_bits(f32_bits)), f);
            }
        }
    }

    #[test]
    fn signaling_nans_survive() {
        let snan32 = 0x7f80_0001u32;
        let f = from_f32(snan32);
        assert_eq!(f.to_bits(), 0x7ff0_0000_2000_0000);
        assert_eq!(to_f32(f), Some(snan32));
        assert_eq!(to_f16(f), None);
        assert_eq!(from_f16(0x7c01).to_bits(), 0x7ff0_0400_0000_0000);
    }

    #[test]
    fn f32_subnormals() {
        for b in [1u32, 2, 0x7f_ffff, 0x40_0000, 0x8000_0001] {
            let f = from_f32(b);
            assert_eq!(f, f64::from(f32::from_bits(b)));
            assert_eq!(to_f32(f), Some(b));
        }
        assert_eq!(to_f32(f64::from_bits(1)), None);
    }
}
