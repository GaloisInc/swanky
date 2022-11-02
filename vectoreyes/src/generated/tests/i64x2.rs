// @generated
// rustfmt-format_generated_files: false
// This file was auto-generated by generate.py DO NOT MODIFY
use super::scalar;
use crate::ExtendingCast;
use crate::SimdBase;
use crate::SimdBase32;
use crate::SimdBase4x;
use crate::SimdBase4x64;
use crate::SimdBase64;
use crate::SimdBase8;
use crate::SimdBase8x;
use crate::SimdBaseGatherable;
use proptest::prelude::*;
use std::ops::*;
proptest! { #[test] fn test_equality( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); a == b }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); a == b }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_is_zero( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); a.is_zero() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); a.is_zero() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_set_lo( a in any::<i64>(), ) { let scalar_out = { use scalar::*; let a: i64 = a.into(); I64x2::set_lo(a).as_array() }; let platform_out = { use crate::*; let a: i64 = a.into(); I64x2::set_lo(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_broadcast( a in any::<i64>(), ) { let scalar_out = { use scalar::*; let a: i64 = a.into(); I64x2::broadcast(a).as_array() }; let platform_out = { use crate::*; let a: i64 = a.into(); I64x2::broadcast(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_broadcast_lo( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); I64x2::broadcast_lo(a).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); I64x2::broadcast_lo(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitxor( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.bitxor(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.bitxor(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitand( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.bitand(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.bitand(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitor( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.bitor(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.bitor(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_add( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.add(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.add(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_sub( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.sub(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.sub(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_shl( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.shl(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.shl(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_shr( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.shr(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.shr(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_cmp_eq( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.cmp_eq(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.cmp_eq(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_unpack_lo( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.unpack_lo(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.unpack_lo(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_unpack_hi( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.unpack_hi(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.unpack_hi(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_min( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.min(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.min(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_max( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.max(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.max(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_cmp_gt( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.cmp_gt(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.cmp_gt(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_and_not( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.and_not(b)).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); (a.and_not(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left_1( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let out = (a.shift_left::<1>()).as_array(); prop_assert_eq!((a << 1).as_array(), out); out }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let out = (a.shift_left::<1>()).as_array(); prop_assert_eq!((a << 1).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right_1( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let out = (a.shift_right::<1>()).as_array(); prop_assert_eq!((a >> 1).as_array(), out); out }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let out = (a.shift_right::<1>()).as_array(); prop_assert_eq!((a >> 1).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left_5( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let out = (a.shift_left::<5>()).as_array(); prop_assert_eq!((a << 5).as_array(), out); out }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let out = (a.shift_left::<5>()).as_array(); prop_assert_eq!((a << 5).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right_5( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let out = (a.shift_right::<5>()).as_array(); prop_assert_eq!((a >> 5).as_array(), out); out }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let out = (a.shift_right::<5>()).as_array(); prop_assert_eq!((a >> 5).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extract_0( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); a.extract::<0>() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); a.extract::<0>() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extract_1( a in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); a.extract::<1>() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); a.extract::<1>() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i8x16( a in any::<[i8; 16]>(), ) { let scalar_out = { use scalar::*; let a: I8x16 = a.into(); I64x2::from(a).as_array() }; let platform_out = { use crate::*; let a: I8x16 = a.into(); I64x2::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i16x8( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); I64x2::from(a).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); I64x2::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i32x4( a in any::<[i32; 4]>(), ) { let scalar_out = { use scalar::*; let a: I32x4 = a.into(); I64x2::from(a).as_array() }; let platform_out = { use crate::*; let a: I32x4 = a.into(); I64x2::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u8x16( a in any::<[u8; 16]>(), ) { let scalar_out = { use scalar::*; let a: U8x16 = a.into(); I64x2::from(a).as_array() }; let platform_out = { use crate::*; let a: U8x16 = a.into(); I64x2::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u16x8( a in any::<[u16; 8]>(), ) { let scalar_out = { use scalar::*; let a: U16x8 = a.into(); I64x2::from(a).as_array() }; let platform_out = { use crate::*; let a: U16x8 = a.into(); I64x2::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u32x4( a in any::<[u32; 4]>(), ) { let scalar_out = { use scalar::*; let a: U32x4 = a.into(); I64x2::from(a).as_array() }; let platform_out = { use crate::*; let a: U32x4 = a.into(); I64x2::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u64x2( a in any::<[u64; 2]>(), ) { let scalar_out = { use scalar::*; let a: U64x2 = a.into(); I64x2::from(a).as_array() }; let platform_out = { use crate::*; let a: U64x2 = a.into(); I64x2::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left( a in any::<[i64; 2]>(), amm in any::<u64>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let amm: u64 = amm.into(); let out = (a << amm).as_array(); prop_assert_eq!((a << I64x2::broadcast(if amm < 64 { amm as i64 } else { 127 })).as_array(), out); out }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let amm: u64 = amm.into(); let out = (a << amm).as_array(); prop_assert_eq!((a << I64x2::broadcast(if amm < 64 { amm as i64 } else { 127 })).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right( a in any::<[i64; 2]>(), amm in any::<u64>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let amm: u64 = amm.into(); let out = (a >> amm).as_array(); prop_assert_eq!((a >> I64x2::broadcast(if amm < 64 { amm as i64 } else { 127 })).as_array(), out); out }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let amm: u64 = amm.into(); let out = (a >> amm).as_array(); prop_assert_eq!((a >> I64x2::broadcast(if amm < 64 { amm as i64 } else { 127 })).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_mul_lo( a in any::<[i64; 2]>(), b in any::<[i64; 2]>(), ) { let scalar_out = { use scalar::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); a.mul_lo(b).as_array() }; let platform_out = { use crate::*; let a: I64x2 = a.into(); let b: I64x2 = b.into(); a.mul_lo(b).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extending_cast_i8x16( a in any::<[i8; 16]>(), ) { let scalar_out = { use scalar::*; let a: I8x16 = a.into(); I64x2::extending_cast_from(a).as_array() }; let platform_out = { use crate::*; let a: I8x16 = a.into(); I64x2::extending_cast_from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extending_cast_i16x8( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); I64x2::extending_cast_from(a).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); I64x2::extending_cast_from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extending_cast_i32x4( a in any::<[i32; 4]>(), ) { let scalar_out = { use scalar::*; let a: I32x4 = a.into(); I64x2::extending_cast_from(a).as_array() }; let platform_out = { use crate::*; let a: I32x4 = a.into(); I64x2::extending_cast_from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_gather_masked_u64( data_0 in any::<[i64 ; 32]>(), data_1 in any::<[i64 ; 32]>(), data_2 in any::<[i64 ; 32]>(), data_3 in any::<[i64 ; 32]>(), idx_0 in 0..128_u64 , idx_1 in 0..128_u64 , src in any::<[i64; 2]>(), mask in any::<[bool; 2]>(), ) { let mut data = vec![0; 128]; data[0..32].copy_from_slice(&data_0); data[32..64].copy_from_slice(&data_1); data[64..96].copy_from_slice(&data_2); data[96..128].copy_from_slice(&data_3); let idx = [ idx_0, idx_1, ]; let safe_out = [ if mask[0] { data[ usize::try_from(idx_0 ).unwrap() ] } else { src[0] } , if mask[1] { data[ usize::try_from(idx_1 ).unwrap() ] } else { src[1] } , ]; let scalar_out = { use scalar::*; let idx = U64x2::from(idx); unsafe { I64x2::gather_masked( data.as_ptr() , idx, I64x2::from([ ((mask[0] as u64) << 63) as i64, ((mask[1] as u64) << 63) as i64, ]), I64x2::from(src), ) }.as_array() }; let crate_out = { use crate::*; let idx = U64x2::from(idx); unsafe { I64x2::gather_masked( data.as_ptr() , idx, I64x2::from([ ((mask[0] as u64) << 63) as i64, ((mask[1] as u64) << 63) as i64, ]), I64x2::from(src), ) }.as_array() }; prop_assert_eq!(scalar_out, safe_out); prop_assert_eq!(scalar_out, crate_out); } }
proptest! { #[test] fn test_gather_u64( data_0 in any::<[i64 ; 32]>(), data_1 in any::<[i64 ; 32]>(), data_2 in any::<[i64 ; 32]>(), data_3 in any::<[i64 ; 32]>(), idx_0 in 0..128_u64 , idx_1 in 0..128_u64 , ) { let mut data = vec![0; 128]; data[0..32].copy_from_slice(&data_0); data[32..64].copy_from_slice(&data_1); data[64..96].copy_from_slice(&data_2); data[96..128].copy_from_slice(&data_3); let idx = [ idx_0, idx_1, ]; let safe_out = [ data[ usize::try_from(idx_0 ).unwrap() ] , data[ usize::try_from(idx_1 ).unwrap() ] , ]; let scalar_out = { use scalar::*; let idx = U64x2::from(idx); unsafe { I64x2::gather( data.as_ptr() , idx, ) }.as_array() }; let crate_out = { use crate::*; let idx = U64x2::from(idx); unsafe { I64x2::gather( data.as_ptr() , idx, ) }.as_array() }; prop_assert_eq!(scalar_out, safe_out); prop_assert_eq!(scalar_out, crate_out); } }
proptest! { #[test] fn test_gather_masked_i64( data_0 in any::<[i64 ; 32]>(), data_1 in any::<[i64 ; 32]>(), data_2 in any::<[i64 ; 32]>(), data_3 in any::<[i64 ; 32]>(), idx_0 in -64..64_i64 , idx_1 in -64..64_i64 , src in any::<[i64; 2]>(), mask in any::<[bool; 2]>(), ) { let mut data = vec![0; 128]; data[0..32].copy_from_slice(&data_0); data[32..64].copy_from_slice(&data_1); data[64..96].copy_from_slice(&data_2); data[96..128].copy_from_slice(&data_3); let idx = [ idx_0, idx_1, ]; let safe_out = [ if mask[0] { data[ usize::try_from(idx_0 + 64 ).unwrap() ] } else { src[0] } , if mask[1] { data[ usize::try_from(idx_1 + 64 ).unwrap() ] } else { src[1] } , ]; let scalar_out = { use scalar::*; let idx = I64x2::from(idx); unsafe { I64x2::gather_masked( data.as_ptr() .offset(64) , idx, I64x2::from([ ((mask[0] as u64) << 63) as i64, ((mask[1] as u64) << 63) as i64, ]), I64x2::from(src), ) }.as_array() }; let crate_out = { use crate::*; let idx = I64x2::from(idx); unsafe { I64x2::gather_masked( data.as_ptr() .offset(64) , idx, I64x2::from([ ((mask[0] as u64) << 63) as i64, ((mask[1] as u64) << 63) as i64, ]), I64x2::from(src), ) }.as_array() }; prop_assert_eq!(scalar_out, safe_out); prop_assert_eq!(scalar_out, crate_out); } }
proptest! { #[test] fn test_gather_i64( data_0 in any::<[i64 ; 32]>(), data_1 in any::<[i64 ; 32]>(), data_2 in any::<[i64 ; 32]>(), data_3 in any::<[i64 ; 32]>(), idx_0 in -64..64_i64 , idx_1 in -64..64_i64 , ) { let mut data = vec![0; 128]; data[0..32].copy_from_slice(&data_0); data[32..64].copy_from_slice(&data_1); data[64..96].copy_from_slice(&data_2); data[96..128].copy_from_slice(&data_3); let idx = [ idx_0, idx_1, ]; let safe_out = [ data[ usize::try_from(idx_0 + 64 ).unwrap() ] , data[ usize::try_from(idx_1 + 64 ).unwrap() ] , ]; let scalar_out = { use scalar::*; let idx = I64x2::from(idx); unsafe { I64x2::gather( data.as_ptr() .offset(64) , idx, ) }.as_array() }; let crate_out = { use crate::*; let idx = I64x2::from(idx); unsafe { I64x2::gather( data.as_ptr() .offset(64) , idx, ) }.as_array() }; prop_assert_eq!(scalar_out, safe_out); prop_assert_eq!(scalar_out, crate_out); } }
#[test]
fn zero_is_zero() {
    assert!(crate::I64x2::ZERO.is_zero());
}
#[test]
fn const_matches_from() {
    const ARR: [i64; 2] = [0, 1];
    assert_eq!(crate::I64x2::from(ARR), crate::I64x2::from_array(ARR),);
}
