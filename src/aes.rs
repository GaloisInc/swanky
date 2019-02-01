// -*- mode: rust; -*-
//
// This file is part of ocelot.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

//! Implementation of AES-128 using Intel's AES-NI.

pub struct Aes128 {
    round_keys: [u8; 176],
}

impl Aes128 {
    #[inline(always)]
    pub fn new(key: &[u8; 16]) -> Self {
        let mut rk = [0u8; 176];
        unsafe {
            asm!("
            movdqu ($1), %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x01, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x02, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x04, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x08, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x10, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x20, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x40, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x80, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x1b, %xmm1, %xmm2;
            pshufd $$0xff, %xmm2, %xmm2;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x4, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            vpslldq $$0x04, %xmm1, %xmm3;
            pxor %xmm3, %xmm1;
            pxor %xmm2, %xmm1;
            movdqu %xmm1, ($0); add $$0x10, $0;
            aeskeygenassist $$0x36, %xmm1, %xmm2;"
                 : "+r"(rk.as_mut_ptr())
                 : "r"(key.as_ptr())
                 : "xmm1", "xmm2", "xmm3", "memory");
        }
        Aes128 { round_keys: rk }
    }
    #[inline]
    pub fn encrypt_u8(&self, m: &[u8; 16]) -> [u8; 16] {
        let mut c = [0; 16];
        unsafe {
            asm!("
            movdqu ($2), %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            pxor %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0; add $$0x10, $1;
            aesenc %xmm0, %xmm1;
            movdqu ($1), %xmm0;
            aesenclast %xmm0, %xmm1;
            movdqu %xmm1, ($3);"
            : "+&r" (10), "+&r" (self.round_keys.as_ptr()) // outputs
            : "r" (m.as_ptr()), "r" (c.as_mut_ptr()) // inputs
            : "xmm0", "xmm1", "memory", "cc" // clobbers
            );
        }
        c
    }
}
