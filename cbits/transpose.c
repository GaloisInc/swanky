#include <stdint.h>
#include <stdlib.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <assert.h>

//Modified from
//https://mischasan.wordpress.com/2011/10/03/the-full-sse2-bit-matrix-transpose-routine/
// with inner most loops changed to _mm_set_epi8 and _mm_set_epi16
void sse_trans(uint8_t *out, uint8_t const *inp, uint64_t nrows, uint64_t ncols) {
#   define INP(x,y) inp[(x)*ncols/8 + (y)/8]
#   define OUT(x,y) out[(y)*nrows/8 + (x)/8]
    uint64_t rr, cc;
    int i, h;
    union { __m128i x; uint8_t b[16]; } tmp;
    __m128i vec;
    assert(nrows % 8 == 0 && ncols % 8 == 0);

    // Do the main body in 16x8 blocks:
    for (rr = 0; rr <= nrows - 16; rr += 16) {
        for (cc = 0; cc < ncols; cc += 8) {
            vec = _mm_set_epi8(
                INP(rr+15,cc),INP(rr+14,cc),INP(rr+13,cc),INP(rr+12,cc),INP(rr+11,cc),INP(rr+10,cc),INP(rr+9,cc),
                INP(rr+8,cc),INP(rr+7,cc),INP(rr+6,cc),INP(rr+5,cc),INP(rr+4,cc),INP(rr+3,cc),INP(rr+2,cc),INP(rr+1,cc),
                INP(rr+0,cc));
            for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1))
                *(uint16_t*)&OUT(rr,cc+i)= _mm_movemask_epi8(vec);
        }
    }
    if (rr == nrows) return;

    // The remainder is a block of 8x(16n+8) bits (n may be 0).
    //  Do a PAIR of 8x8 blocks in each step:
    for (cc = 0; cc <= ncols - 16; cc += 16) {
        vec = _mm_set_epi16(
            *(uint16_t const*)&INP(rr + 7, cc), *(uint16_t const*)&INP(rr + 6, cc),
            *(uint16_t const*)&INP(rr + 5, cc), *(uint16_t const*)&INP(rr + 4, cc),
            *(uint16_t const*)&INP(rr + 3, cc), *(uint16_t const*)&INP(rr + 2, cc),
            *(uint16_t const*)&INP(rr + 1, cc), *(uint16_t const*)&INP(rr + 0, cc));
        for (i = 8; --i >= 0; vec = _mm_slli_epi64(vec, 1)) {
            OUT(rr, cc + i) = h = _mm_movemask_epi8(vec);
            OUT(rr, cc + i + 8) = h >> 8;
        }
    }
    if (cc == ncols) return;

    //  Do the remaining 8x8 block:
    for (i = 0; i < 8; ++i)
        tmp.b[i] = INP(rr + i, cc);
    for (i = 8; --i >= 0; tmp.x = _mm_slli_epi64(tmp.x, 1))
        OUT(rr, cc + i) = _mm_movemask_epi8(tmp.x);
#undef INP
#undef OUT
}
