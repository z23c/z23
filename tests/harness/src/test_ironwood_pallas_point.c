/* purpose: Compare isolated Jacobian Pallas operations with upstream vectors. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "../../../engine/services/src/ironwood_pallas_point.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>
/* pasta_curves 0.6.0 point-oracle.rs SHA256
 * 68dc78c014c8af19aee21612524979b861883cce4db9b1edbaa9f0253131b551;
 * fixture SHA256 89a683fca79d8d6919adeaa5d56885e1fcd33bfdda17b37475123a9f069d5f2b. */
static bool read_point(struct pallas_point *out, const char *x, const char *y)
{
    struct pallas_point p = { .y = {{1,0,0,0}} };
    if (!strcmp(x,"I") && !strcmp(y,"I")) { *out = p; return true; }
    uint8_t xb[32], yb[32];
    if (!zcl_hex_decode(x,xb,32) || !zcl_hex_decode(y,yb,32) ||
        !pallas_fp_read(&p.x,xb).ok || !pallas_fp_read(&p.y,yb).ok) return false;
    p.z.limb[0] = 1; *out = p; return true;
}
static bool matches(const struct pallas_point *p, const char *x, const char *y)
{
    const struct pallas_fp zero = {{0}};
    if (!memcmp(&p->z,&zero,sizeof zero)) return !strcmp(x,"I") && !strcmp(y,"I");
    struct pallas_fp inv, square, cube, ax, ay;
    uint8_t xb[32], yb[32], wantx[32], wanty[32];
    if (!pallas_fp_invert(&inv,&p->z).ok || !zcl_hex_decode(x,wantx,32) ||
        !zcl_hex_decode(y,wanty,32)) return false;
    pallas_fp_mul(&square,&inv,&inv); pallas_fp_mul(&cube,&square,&inv);
    pallas_fp_mul(&ax,&p->x,&square); pallas_fp_mul(&ay,&p->y,&cube);
    pallas_fp_write(xb,&ax); pallas_fp_write(yb,&ay);
    return !memcmp(xb,wantx,32) && !memcmp(yb,wanty,32);
}
static void scale_point(struct pallas_point *p)
{
    struct pallas_fp four = {{4,0,0,0}}, eight = {{8,0,0,0}}, two = {{2,0,0,0}};
    pallas_fp_mul(&p->x,&p->x,&four); pallas_fp_mul(&p->y,&p->y,&eight);
    pallas_fp_mul(&p->z,&p->z,&two);
}
static bool row(char value[6][65], size_t index)
{
    struct pallas_point a,b,r,copy;
    if (!read_point(&a,value[0],value[1]) || !read_point(&b,value[2],value[3])) return false;
    pallas_point_add(&r,&a,&b); if (!matches(&r,value[4],value[5])) return false;
    copy = a; pallas_point_add(&copy,&copy,&b); if (!matches(&copy,value[4],value[5])) return false;
    copy = b; pallas_point_add(&copy,&a,&copy); if (!matches(&copy,value[4],value[5])) return false;
    copy = a; scale_point(&copy); pallas_point_add(&r,&copy,&b);
    if (!matches(&r,value[4],value[5])) return false;
    copy = b; scale_point(&copy); pallas_point_add(&r,&a,&copy);
    if (!matches(&r,value[4],value[5])) return false;
    scale_point(&a); scale_point(&b); pallas_point_add(&r,&a,&b);
    if (!matches(&r,value[4],value[5])) return false;
    if (index == 0 || index == 3) {
        pallas_point_double(&a,&a); if (!matches(&a,value[4],value[5])) return false;
    }
    return true;
}
int test_ironwood_pallas_point(void)
{
    FILE *f = fopen("tests/fixtures/ironwood/pallas-point-add.txt","r");
    if (!f) return 1;
    char value[6][65]; size_t count = 0; bool ok = true;
    while (fscanf(f,"%64s%64s%64s%64s%64s%64s",value[0],value[1],value[2],value[3],value[4],value[5]) == 6) {
        if (!row(value,count++)) { ok = false; break; }
    }
    if (ferror(f)) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok && count == 37 ? 0 : 1;
}
