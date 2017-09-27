#ifndef __DV_PT_HDRS__
#define __DV_PT_HDRS__

#include <inttypes.h>

typedef struct frm_raw
{
        uint8_t bytes[85536];
} frame_raw;

typedef struct frm_ethII
{
        uint8_t dst[6];
        uint8_t src[6];
        uint8_t ethtp[2];
        uint8_t payload[1518];
        /* FCF */
} frame_ethII;

typedef struct frm_ethIIv
{
        uint8_t dst[6];
        uint8_t src[6];
        uint8_t vln[4];
        uint8_t ethtp[2];
        uint8_t payload[1522];
        /* FCF */
} frame_ethIIv;

typedef struct frm_8023
{
        uint8_t dst[6];
        uint8_t src[6];
        uint8_t len[2];
        uint8_t ident[2];
        uint8_t payload[1522];
        /* FCF */
} frame_8023;

typedef struct frm_8023_llc
{
        uint8_t dst[6];
        uint8_t src[6];
        uint8_t len[2];
        uint8_t dsap;
        uint8_t ssap;
        uint8_t payload[1520];  /* ??? */
        /* FCF */
} frame_8023_llc;

#endif /* __DV_PT_HDRS__ */
