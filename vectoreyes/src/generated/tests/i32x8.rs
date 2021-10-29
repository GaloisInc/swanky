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
proptest! { #[test] fn test_equality( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a == b }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a == b }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_is_zero( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); a.is_zero() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); a.is_zero() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_set_lo( a in any::<i32>(), ) { let scalar_out = { use scalar::*; let a: i32 = a.into(); I32x8::set_lo(a).as_array() }; let platform_out = { use crate::*; let a: i32 = a.into(); I32x8::set_lo(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_broadcast( a in any::<i32>(), ) { let scalar_out = { use scalar::*; let a: i32 = a.into(); I32x8::broadcast(a).as_array() }; let platform_out = { use crate::*; let a: i32 = a.into(); I32x8::broadcast(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_broadcast_lo( a in any::<[i32; 4]>(), ) { let scalar_out = { use scalar::*; let a: I32x4 = a.into(); I32x8::broadcast_lo(a).as_array() }; let platform_out = { use crate::*; let a: I32x4 = a.into(); I32x8::broadcast_lo(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitxor( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.bitxor(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.bitxor(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitand( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.bitand(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.bitand(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_bitor( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.bitor(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.bitor(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_add( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.add(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.add(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_sub( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.sub(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.sub(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_shl( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.shl(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.shl(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_shr( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.shr(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.shr(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_cmp_eq( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.cmp_eq(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.cmp_eq(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_unpack_lo( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.unpack_lo(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.unpack_lo(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_unpack_hi( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.unpack_hi(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.unpack_hi(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_min( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.min(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.min(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_max( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.max(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.max(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_binop_cmp_gt( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.cmp_gt(b)).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); (a.cmp_gt(b)).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left_1( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let out = (a.shift_left::<1>()).as_array(); prop_assert_eq!((a << 1).as_array(), out); out }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let out = (a.shift_left::<1>()).as_array(); prop_assert_eq!((a << 1).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right_1( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let out = (a.shift_right::<1>()).as_array(); prop_assert_eq!((a >> 1).as_array(), out); out }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let out = (a.shift_right::<1>()).as_array(); prop_assert_eq!((a >> 1).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left_5( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let out = (a.shift_left::<5>()).as_array(); prop_assert_eq!((a << 5).as_array(), out); out }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let out = (a.shift_left::<5>()).as_array(); prop_assert_eq!((a << 5).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right_5( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let out = (a.shift_right::<5>()).as_array(); prop_assert_eq!((a >> 5).as_array(), out); out }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let out = (a.shift_right::<5>()).as_array(); prop_assert_eq!((a >> 5).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extract_0( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); a.extract::<0>() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); a.extract::<0>() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_extract_1( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); a.extract::<1>() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); a.extract::<1>() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i8x32( a in any::<[i8; 32]>(), ) { let scalar_out = { use scalar::*; let a: I8x32 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I8x32 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i16x16( a in any::<[i16; 16]>(), ) { let scalar_out = { use scalar::*; let a: I16x16 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I16x16 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_i64x4( a in any::<[i64; 4]>(), ) { let scalar_out = { use scalar::*; let a: I64x4 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I64x4 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u8x32( a in any::<[u8; 32]>(), ) { let scalar_out = { use scalar::*; let a: U8x32 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U8x32 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u16x16( a in any::<[u16; 16]>(), ) { let scalar_out = { use scalar::*; let a: U16x16 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U16x16 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u32x8( a in any::<[u32; 8]>(), ) { let scalar_out = { use scalar::*; let a: U32x8 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U32x8 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_cast_from_u64x4( a in any::<[u64; 4]>(), ) { let scalar_out = { use scalar::*; let a: U64x4 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: U64x4 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_left( a in any::<[i32; 8]>(), amm in any::<u64>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let amm: u64 = amm.into(); let out = (a << amm).as_array(); prop_assert_eq!((a << I32x8::broadcast(if amm < 32 { amm as i32 } else { 127 })).as_array(), out); out }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let amm: u64 = amm.into(); let out = (a << amm).as_array(); prop_assert_eq!((a << I32x8::broadcast(if amm < 32 { amm as i32 } else { 127 })).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shift_right( a in any::<[i32; 8]>(), amm in any::<u64>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let amm: u64 = amm.into(); let out = (a >> amm).as_array(); prop_assert_eq!((a >> I32x8::broadcast(if amm < 32 { amm as i32 } else { 127 })).as_array(), out); out }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let amm: u64 = amm.into(); let out = (a >> amm).as_array(); prop_assert_eq!((a >> I32x8::broadcast(if amm < 32 { amm as i32 } else { 127 })).as_array(), out); out }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shuffle_0_1_2_3( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); a.shuffle::<0, 1, 2, 3>().as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); a.shuffle::<0, 1, 2, 3>().as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shuffle_3_2_1_0( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); a.shuffle::<3, 2, 1, 0>().as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); a.shuffle::<3, 2, 1, 0>().as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_shuffle_3_3_3_3( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); a.shuffle::<3, 3, 3, 3>().as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); a.shuffle::<3, 3, 3, 3>().as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_from_128( a in any::<[i32; 4]>(), ) { let scalar_out = { use scalar::*; let a: I32x4 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I32x4 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_set_pair( a in any::<[i32; 4]>(), b in any::<[i32; 4]>(), ) { let scalar_out = { use scalar::*; let a: I32x4 = a.into(); let b: I32x4 = b.into(); I32x8::from([a, b]).as_array() }; let platform_out = { use crate::*; let a: I32x4 = a.into(); let b: I32x4 = b.into(); I32x8::from([a, b]).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_to_pair( a in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let [lo, hi] = <[I32x4; 2]>::from(a); [lo.as_array(), hi.as_array()] }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let [lo, hi] = <[I32x4; 2]>::from(a); [lo.as_array(), hi.as_array()] }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_from_i16x8( a in any::<[i16; 8]>(), ) { let scalar_out = { use scalar::*; let a: I16x8 = a.into(); I32x8::from(a).as_array() }; let platform_out = { use crate::*; let a: I16x8 = a.into(); I32x8::from(a).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_blend_0( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a.blend::< false, false, false, false, false, false, false, false, >(b).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a.blend::< false, false, false, false, false, false, false, false, >(b).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_blend_255( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a.blend::< true, true, true, true, true, true, true, true, >(b).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a.blend::< true, true, true, true, true, true, true, true, >(b).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_blend_101( a in any::<[i32; 8]>(), b in any::<[i32; 8]>(), ) { let scalar_out = { use scalar::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a.blend::< true, false, true, false, false, true, true, false, >(b).as_array() }; let platform_out = { use crate::*; let a: I32x8 = a.into(); let b: I32x8 = b.into(); a.blend::< true, false, true, false, false, true, true, false, >(b).as_array() }; prop_assert_eq!(scalar_out, platform_out); } }
proptest! { #[test] fn test_gather_masked_i32( data_0 in any::<[i32 ; 32]>(), data_1 in any::<[i32 ; 32]>(), data_2 in any::<[i32 ; 32]>(), data_3 in any::<[i32 ; 32]>(), idx_0 in -64..64_i32 , idx_1 in -64..64_i32 , idx_2 in -64..64_i32 , idx_3 in -64..64_i32 , idx_4 in -64..64_i32 , idx_5 in -64..64_i32 , idx_6 in -64..64_i32 , idx_7 in -64..64_i32 , src in any::<[i32; 8]>(), mask in any::<[bool; 8]>(), ) { let mut data = vec![0; 128]; data[0..32].copy_from_slice(&data_0); data[32..64].copy_from_slice(&data_1); data[64..96].copy_from_slice(&data_2); data[96..128].copy_from_slice(&data_3); let idx = [ idx_0, idx_1, idx_2, idx_3, idx_4, idx_5, idx_6, idx_7, ]; let safe_out = [ if mask[0] { data[ usize::try_from(idx_0 + 64 ).unwrap() ] } else { src[0] } , if mask[1] { data[ usize::try_from(idx_1 + 64 ).unwrap() ] } else { src[1] } , if mask[2] { data[ usize::try_from(idx_2 + 64 ).unwrap() ] } else { src[2] } , if mask[3] { data[ usize::try_from(idx_3 + 64 ).unwrap() ] } else { src[3] } , if mask[4] { data[ usize::try_from(idx_4 + 64 ).unwrap() ] } else { src[4] } , if mask[5] { data[ usize::try_from(idx_5 + 64 ).unwrap() ] } else { src[5] } , if mask[6] { data[ usize::try_from(idx_6 + 64 ).unwrap() ] } else { src[6] } , if mask[7] { data[ usize::try_from(idx_7 + 64 ).unwrap() ] } else { src[7] } , ]; let scalar_out = { use scalar::*; let idx = I32x8::from(idx); unsafe { I32x8::gather_masked( data.as_ptr() .offset(64) , idx, I32x8::from([ ((mask[0] as u32) << 31) as i32, ((mask[1] as u32) << 31) as i32, ((mask[2] as u32) << 31) as i32, ((mask[3] as u32) << 31) as i32, ((mask[4] as u32) << 31) as i32, ((mask[5] as u32) << 31) as i32, ((mask[6] as u32) << 31) as i32, ((mask[7] as u32) << 31) as i32, ]), I32x8::from(src), ) }.as_array() }; let crate_out = { use crate::*; let idx = I32x8::from(idx); unsafe { I32x8::gather_masked( data.as_ptr() .offset(64) , idx, I32x8::from([ ((mask[0] as u32) << 31) as i32, ((mask[1] as u32) << 31) as i32, ((mask[2] as u32) << 31) as i32, ((mask[3] as u32) << 31) as i32, ((mask[4] as u32) << 31) as i32, ((mask[5] as u32) << 31) as i32, ((mask[6] as u32) << 31) as i32, ((mask[7] as u32) << 31) as i32, ]), I32x8::from(src), ) }.as_array() }; prop_assert_eq!(scalar_out, safe_out); prop_assert_eq!(scalar_out, crate_out); } }
proptest! { #[test] fn test_gather_i32( data_0 in any::<[i32 ; 32]>(), data_1 in any::<[i32 ; 32]>(), data_2 in any::<[i32 ; 32]>(), data_3 in any::<[i32 ; 32]>(), idx_0 in -64..64_i32 , idx_1 in -64..64_i32 , idx_2 in -64..64_i32 , idx_3 in -64..64_i32 , idx_4 in -64..64_i32 , idx_5 in -64..64_i32 , idx_6 in -64..64_i32 , idx_7 in -64..64_i32 , ) { let mut data = vec![0; 128]; data[0..32].copy_from_slice(&data_0); data[32..64].copy_from_slice(&data_1); data[64..96].copy_from_slice(&data_2); data[96..128].copy_from_slice(&data_3); let idx = [ idx_0, idx_1, idx_2, idx_3, idx_4, idx_5, idx_6, idx_7, ]; let safe_out = [ data[ usize::try_from(idx_0 + 64 ).unwrap() ] , data[ usize::try_from(idx_1 + 64 ).unwrap() ] , data[ usize::try_from(idx_2 + 64 ).unwrap() ] , data[ usize::try_from(idx_3 + 64 ).unwrap() ] , data[ usize::try_from(idx_4 + 64 ).unwrap() ] , data[ usize::try_from(idx_5 + 64 ).unwrap() ] , data[ usize::try_from(idx_6 + 64 ).unwrap() ] , data[ usize::try_from(idx_7 + 64 ).unwrap() ] , ]; let scalar_out = { use scalar::*; let idx = I32x8::from(idx); unsafe { I32x8::gather( data.as_ptr() .offset(64) , idx, ) }.as_array() }; let crate_out = { use crate::*; let idx = I32x8::from(idx); unsafe { I32x8::gather( data.as_ptr() .offset(64) , idx, ) }.as_array() }; prop_assert_eq!(scalar_out, safe_out); prop_assert_eq!(scalar_out, crate_out); } }
#[test]
fn zero_is_zero() {
    assert!(crate::I32x8::ZERO.is_zero());
}
#[test]
fn const_matches_from() {
    const ARR: [i32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    assert_eq!(crate::I32x8::from(ARR), crate::I32x8::from_array(ARR),);
}
