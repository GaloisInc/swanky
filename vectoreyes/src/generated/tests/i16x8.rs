// @generated
// rustfmt-format_generated_files: false
// This file was auto-generated by generate.py DO NOT MODIFY
use super::scalar;
use crate::SimdBase;
use crate::SimdBase32;
use crate::SimdBase4x;
use crate::SimdBase4x64;
use crate::SimdBase64;
use crate::SimdBase8;
use crate::SimdBase8x;
use crate::SimdBaseGatherable;
use crate::SimdBaseSigned;
use proptest::prelude::*;
use std::convert::TryFrom;
use std::ops::*;
proptest! { #[test] fn test_equality( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a == b }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a == b }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_is_zero( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); a.is_zero() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); a.is_zero() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_set_lo( a in any::<i16>(), ) { let scalar_out = { use scalar::*; let a: i16 = a.into(); I16x8::set_lo(a).as_array() }; let platform_out = { use crate::*; let a: i16 = a.into(); I16x8::set_lo(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_broadcast( a in any::<i16>(), ) { let scalar_out = { use scalar::*; let a: i16 = a.into(); I16x8::broadcast(a).as_array() }; let platform_out = { use crate::*; let a: i16 = a.into(); I16x8::broadcast(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_broadcast_lo( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); I16x8::broadcast_lo(a).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); I16x8::broadcast_lo(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitxor( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.bitxor(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.bitxor(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitand( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.bitand(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.bitand(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitor( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.bitor(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.bitor(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_add( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.add(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.add(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_sub( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.sub(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.sub(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_shl( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.shl(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.shl(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_shr( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.shr(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.shr(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_cmp_eq( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.cmp_eq(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.cmp_eq(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_unpack_lo( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.unpack_lo(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.unpack_lo(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_unpack_hi( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.unpack_hi(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.unpack_hi(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_min( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.min(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.min(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_max( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.max(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.max(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_cmp_gt( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.cmp_gt(b)).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); (a.cmp_gt(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left_1( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let out = (a.shift_left::<1>()).as_array(); prop_assert_eq!((a << 1).as_array(), out); out }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let out = (a.shift_left::<1>()).as_array(); prop_assert_eq!((a << 1).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right_1( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let out = (a.shift_right::<1>()).as_array(); prop_assert_eq!((a >> 1).as_array(), out); out }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let out = (a.shift_right::<1>()).as_array(); prop_assert_eq!((a >> 1).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left_5( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let out = (a.shift_left::<5>()).as_array(); prop_assert_eq!((a << 5).as_array(), out); out }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let out = (a.shift_left::<5>()).as_array(); prop_assert_eq!((a << 5).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right_5( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let out = (a.shift_right::<5>()).as_array(); prop_assert_eq!((a >> 5).as_array(), out); out }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let out = (a.shift_right::<5>()).as_array(); prop_assert_eq!((a >> 5).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extract_0( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); a.extract::<0>() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); a.extract::<0>() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extract_1( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); a.extract::<1>() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); a.extract::<1>() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i8x16( a in any::<[i8; 16]>(), ) { let scalar_out = { use scalar::*; let a: I8x16 = a.into(); I16x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I8x16 = a.into(); I16x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i32x4( a in any::<[i32; 4]>(), ) { let scalar_out = { use scalar::*; let a: I32x4 = a.into(); I16x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I32x4 = a.into(); I16x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i64x2( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); I16x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); I16x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u8x16( a in any::<[u8; 16]>(), ) { let scalar_out = { use scalar::*; let a: U8x16 = a.into(); I16x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U8x16 = a.into(); I16x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u16x8( a in any::<[u16; 8]>(), ) { let scalar_out = { use scalar::*; let a: U16x8 = a.into(); I16x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U16x8 = a.into(); I16x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u32x4( a in any::<[u32; 4]>(), ) { let scalar_out = { use scalar::*; let a: U32x4 = a.into(); I16x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U32x4 = a.into(); I16x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u64x2( a in any::<[u64; 2]>(), ) { let scalar_out = { use scalar::*; let a: U64x2 = a.into(); I16x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U64x2 = a.into(); I16x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left( a in any::<[i16; 8]>(), amm in any::<u64>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let amm: u64 = amm.into(); let out = (a << amm).as_array(); prop_assert_eq!((a << I16x8::broadcast(if amm < 16 { amm as i16 } else { 127 })).as_array(), out); out }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let amm: u64 = amm.into(); let out = (a << amm).as_array(); prop_assert_eq!((a << I16x8::broadcast(if amm < 16 { amm as i16 } else { 127 })).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right( a in any::<[i16; 8]>(), amm in any::<u64>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let amm: u64 = amm.into(); let out = (a >> amm).as_array(); prop_assert_eq!((a >> I16x8::broadcast(if amm < 16 { amm as i16 } else { 127 })).as_array(), out); out }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let amm: u64 = amm.into(); let out = (a >> amm).as_array(); prop_assert_eq!((a >> I16x8::broadcast(if amm < 16 { amm as i16 } else { 127 })).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_blend_0( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a.blend::< false, false, false, false, false, false, false, false, >(b).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a.blend::< false, false, false, false, false, false, false, false, >(b).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_blend_255( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a.blend::< true, true, true, true, true, true, true, true, >(b).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a.blend::< true, true, true, true, true, true, true, true, >(b).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_blend_101( a in any::<[i16; 8]>(), b in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a.blend::< true, false, true, false, false, true, true, false, >(b).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); let b: I16x8 = b.into(); a.blend::< true, false, true, false, false, true, true, false, >(b).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
#[test]
fn zero_is_zero() {
    assert!(crate::I16x8::ZERO.is_zero());
}
#[test]
fn const_matches_from() {
    const ARR: [i16; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    assert_eq!(crate::I16x8::from(ARR), const_i16x8!(ARR),);
}
