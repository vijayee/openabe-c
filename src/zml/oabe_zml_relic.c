///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of Zeutro's OpenABE.
///
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
///
/// \file   oabe_zml_relic.c
///
/// \brief  ZML math layer implementation using RELIC library.
///

#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "openabe/oabe_zml.h"
#include "openabe/oabe_memory.h"
#include "openabe/oabe_internal.h"

/* RELIC includes */
#include <relic.h>

/*============================================================================
 * Helper Macros
 *============================================================================*/

#define BN_GET(zp) ((BIGNUM*)((zp)->value->bn))

/*============================================================================
 * Internal Structures
 *============================================================================*/

typedef struct OABE_Group_Impl {
    OABE_Object base;
    OABE_CurveID curve_id;
    bn_t order;          /* Group order */
    g1_t g1_gen;         /* G1 generator */
    g2_t g2_gen;         /* G2 generator */
} OABE_Group_Impl;

typedef struct OABE_RNG_Impl {
    OABE_Object base;
    uint8_t seed[32];
    bool initialized;
} OABE_RNG_Impl;

typedef struct OABE_ZP_Impl {
    OABE_Object base;
    OABE_GroupHandle group;
    bn_t value;          /* RELIC bn_t for scalar value */
} OABE_ZP_Impl;

typedef struct OABE_G1_Impl {
    OABE_Object base;
    OABE_GroupHandle group;
    g1_t point;           /* RELIC G1 point */
} OABE_G1_Impl;

typedef struct OABE_G2_Impl {
    OABE_Object base;
    OABE_GroupHandle group;
    g2_t point;           /* RELIC G2 point */
} OABE_G2_Impl;

typedef struct OABE_GT_Impl {
    OABE_Object base;
    OABE_GroupHandle group;
    gt_t value;           /* RELIC GT element */
} OABE_GT_Impl;

/*============================================================================
 * VTables
 *============================================================================*/

static void oabe_rng_destroy(void *ptr);
static void oabe_group_destroy(void *ptr);
static void oabe_zp_destroy(void *ptr);
static void oabe_g1_destroy(void *ptr);
static void oabe_g2_destroy(void *ptr);
static void oabe_gt_destroy(void *ptr);

static OABE_ObjectVTable g_rng_vtable = { oabe_rng_destroy, NULL, NULL, NULL };
static OABE_ObjectVTable g_group_vtable = { oabe_group_destroy, NULL, NULL, NULL };
static OABE_ObjectVTable g_zp_vtable = { oabe_zp_destroy, NULL, NULL, NULL };
static OABE_ObjectVTable g_g1_vtable = { oabe_g1_destroy, NULL, NULL, NULL };
static OABE_ObjectVTable g_g2_vtable = { oabe_g2_destroy, NULL, NULL, NULL };
static OABE_ObjectVTable g_gt_vtable = { oabe_gt_destroy, NULL, NULL, NULL };

/*============================================================================
 * RNG Implementation
 *============================================================================*/

OABE_RNGHandle oabe_rng_new(const uint8_t *seed, size_t seed_len) {
    OABE_RNG_Impl *rng = (OABE_RNG_Impl *)oabe_malloc(sizeof(OABE_RNG_Impl));
    if (!rng) return NULL;

    rng->base.ref_count = 1;
    rng->base.vtable = &g_rng_vtable;
    rng->initialized = false;

    if (seed && seed_len > 0) {
        if (seed_len > 32) seed_len = 32;
        memcpy(rng->seed, seed, seed_len);
        rng->initialized = true;
    }

    return (OABE_RNGHandle)rng;
}

void oabe_rng_free(OABE_RNGHandle rng) {
    if (rng) {
        OABE_DEREF(rng);
    }
}

static void oabe_rng_destroy(void *ptr) {
    OABE_RNG_Impl *rng = (OABE_RNG_Impl *)ptr;
    if (rng) {
        oabe_zeroize(rng->seed, sizeof(rng->seed));
        oabe_free(rng);
    }
}

OABE_ERROR oabe_rng_bytes(OABE_RNGHandle rng, uint8_t *output, size_t len) {
    (void)rng; /* Unused - RELIC uses its own RNG */
    if (!output || len == 0) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Use RELIC's RAND_bytes equivalent - returns void */
    rand_bytes(output, len);

    return OABE_SUCCESS;
}

/*============================================================================
 * Group Implementation
 *============================================================================*/

OABE_GroupHandle oabe_group_new(OABE_CurveID curve_id) {
    OABE_Group_Impl *group = (OABE_Group_Impl *)oabe_malloc(sizeof(OABE_Group_Impl));
    if (!group) return NULL;

    group->base.ref_count = 1;
    group->base.vtable = &g_group_vtable;
    group->curve_id = curve_id;

    /* Initialize RELIC core if not already done */
    if (core_get() == NULL) {
        core_init();
    }

    /* Initialize group order */
    bn_null(group->order);
    bn_new(group->order);
    g1_get_ord(group->order);

    /* Initialize generators */
    g1_null(group->g1_gen);
    g1_new(group->g1_gen);
    g1_get_gen(group->g1_gen);

    g2_null(group->g2_gen);
    g2_new(group->g2_gen);
    g2_get_gen(group->g2_gen);

    return (OABE_GroupHandle)group;
}

void oabe_group_free(OABE_GroupHandle group) {
    if (group) {
        OABE_DEREF(group);
    }
}

static void oabe_group_destroy(void *ptr) {
    OABE_Group_Impl *group = (OABE_Group_Impl *)ptr;
    if (group) {
        bn_free(group->order);
        g1_free(group->g1_gen);
        g2_free(group->g2_gen);
        oabe_free(group);
    }
}

OABE_CurveID oabe_group_get_curve_id(OABE_GroupHandle group) {
    if (!group) return OABE_CURVE_NONE;
    return ((OABE_Group_Impl *)group)->curve_id;
}

OABE_ERROR oabe_group_get_order(OABE_GroupHandle group, OABE_ByteString **result) {
    if (!group || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    OABE_Group_Impl *g = (OABE_Group_Impl *)group;

    *result = oabe_bytestring_new();
    if (!*result) return OABE_ERROR_OUT_OF_MEMORY;

    int len = bn_size_bin(g->order);
    uint8_t *buf = (uint8_t *)oabe_malloc(len);
    if (!buf) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    bn_write_bin(buf, len, g->order);
    OABE_ERROR rc = oabe_bytestring_append_data(*result, buf, len);
    oabe_free(buf);

    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
    }

    return rc;
}

/*============================================================================
 * ZP Implementation
 *============================================================================*/

static void oabe_zp_destroy(void *ptr) {
    OABE_ZP_Impl *zp = (OABE_ZP_Impl *)ptr;
    if (zp) {
        bn_free(zp->value);
        if (zp->group) oabe_group_free(zp->group);
        oabe_free(zp);
    }
}

OABE_ZP* oabe_zp_new(OABE_GroupHandle group) {
    if (!group) return NULL;

    OABE_ZP_Impl *zp = (OABE_ZP_Impl *)oabe_malloc(sizeof(OABE_ZP_Impl));
    if (!zp) return NULL;

    zp->base.ref_count = 1;
    zp->base.vtable = &g_zp_vtable;
    zp->group = group;
    OABE_ADDREF(group);

    bn_null(zp->value);
    bn_new(zp->value);
    bn_zero(zp->value);

    return (OABE_ZP *)zp;
}

void oabe_zp_free(OABE_ZP *zp) {
    if (zp) {
        OABE_DEREF(zp);
    }
}

OABE_ZP* oabe_zp_clone(const OABE_ZP *zp) {
    if (!zp) return NULL;

    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    OABE_ZP_Impl *clone = (OABE_ZP_Impl *)oabe_zp_new(impl->group);
    if (!clone) return NULL;

    bn_copy(clone->value, impl->value);
    return (OABE_ZP *)clone;
}

OABE_GroupHandle oabe_zp_get_group(const OABE_ZP *zp) {
    if (!zp) return NULL;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    return impl->group;
}

OABE_ERROR oabe_zp_set_zero(OABE_ZP *zp) {
    if (!zp) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    bn_zero(impl->value);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_set_one(OABE_ZP *zp) {
    if (!zp) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    bn_set_dig(impl->value, 1);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_copy(OABE_ZP *dst, const OABE_ZP *src) {
    if (!dst || !src) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *dst_impl = (OABE_ZP_Impl *)dst;
    OABE_ZP_Impl *src_impl = (OABE_ZP_Impl *)src;
    bn_copy(dst_impl->value, src_impl->value);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_set_int(OABE_ZP *zp, int value) {
    if (!zp) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    if (value >= 0) {
        bn_set_dig(impl->value, (dig_t)value);
    } else {
        bn_set_dig(impl->value, (dig_t)(-value));
        bn_neg(impl->value, impl->value);
    }
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_set_hex(OABE_ZP *zp, const char *hex) {
    if (!zp || !hex) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    bn_read_str(impl->value, hex, strlen(hex), 16);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_set_bytes(OABE_ZP *zp, const uint8_t *data, size_t len) {
    if (!zp || !data || len == 0) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    bn_read_bin(impl->value, data, (int)len);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_random(OABE_ZP *zp, OABE_RNGHandle rng) {
    if (!zp) return OABE_ERROR_INVALID_INPUT;
    (void)rng; /* Unused - RELIC uses its own RNG */

    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    OABE_Group_Impl *g = (OABE_Group_Impl *)impl->group;

    if (!g) return OABE_ERROR_INVALID_INPUT;

    bn_rand_mod(impl->value, g->order);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_add(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *r = (OABE_ZP_Impl *)result;
    OABE_ZP_Impl *ra = (OABE_ZP_Impl *)a;
    OABE_ZP_Impl *rb = (OABE_ZP_Impl *)b;
    OABE_Group_Impl *g = (OABE_Group_Impl *)ra->group;
    bn_add(r->value, ra->value, rb->value);
    bn_mod(r->value, r->value, g->order);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_sub(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *r = (OABE_ZP_Impl *)result;
    OABE_ZP_Impl *ra = (OABE_ZP_Impl *)a;
    OABE_ZP_Impl *rb = (OABE_ZP_Impl *)b;
    OABE_Group_Impl *g = (OABE_Group_Impl *)ra->group;
    bn_sub(r->value, ra->value, rb->value);
    bn_mod(r->value, r->value, g->order);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_mul(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *r = (OABE_ZP_Impl *)result;
    OABE_ZP_Impl *ra = (OABE_ZP_Impl *)a;
    OABE_ZP_Impl *rb = (OABE_ZP_Impl *)b;
    OABE_Group_Impl *g = (OABE_Group_Impl *)ra->group;
    bn_mul(r->value, ra->value, rb->value);
    bn_mod(r->value, r->value, g->order);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_div(OABE_ZP *result, const OABE_ZP *a, const OABE_ZP *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *r = (OABE_ZP_Impl *)result;
    OABE_ZP_Impl *ra = (OABE_ZP_Impl *)a;
    OABE_ZP_Impl *rb = (OABE_ZP_Impl *)b;

    bn_t inv;
    bn_null(inv);
    bn_new(inv);
    bn_mod_inv(inv, rb->value, ((OABE_Group_Impl *)ra->group)->order);
    bn_mul(r->value, ra->value, inv);
    bn_free(inv);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_neg(OABE_ZP *result, const OABE_ZP *a) {
    if (!result || !a) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *r = (OABE_ZP_Impl *)result;
    OABE_ZP_Impl *ra = (OABE_ZP_Impl *)a;
    OABE_Group_Impl *g = (OABE_Group_Impl *)ra->group;
    bn_neg(r->value, ra->value);
    bn_mod(r->value, r->value, g->order);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_zp_inv(OABE_ZP *result, const OABE_ZP *a) {
    if (!result || !a) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *r = (OABE_ZP_Impl *)result;
    OABE_ZP_Impl *ra = (OABE_ZP_Impl *)a;
    OABE_Group_Impl *g = (OABE_Group_Impl *)ra->group;

    if (!g) return OABE_ERROR_INVALID_INPUT;
    bn_mod_inv(r->value, ra->value, g->order);
    return OABE_SUCCESS;
}

int oabe_zp_cmp(const OABE_ZP *a, const OABE_ZP *b) {
    if (!a || !b) return 0;
    OABE_ZP_Impl *ra = (OABE_ZP_Impl *)a;
    OABE_ZP_Impl *rb = (OABE_ZP_Impl *)b;
    return bn_cmp(ra->value, rb->value);
}

bool oabe_zp_is_zero(const OABE_ZP *zp) {
    if (!zp) return false;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    return bn_is_zero(impl->value);
}

bool oabe_zp_is_one(const OABE_ZP *zp) {
    if (!zp) return false;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;
    return bn_cmp_dig(impl->value, 1) == RLC_EQ;
}

char* oabe_zp_to_hex(const OABE_ZP *zp) {
    if (!zp) return NULL;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;

    int len = bn_size_str(impl->value, 16);
    char *hex = (char *)oabe_malloc(len + 1);
    if (!hex) return NULL;

    bn_write_str(hex, len, impl->value, 16);
    return hex;
}

OABE_ERROR oabe_zp_serialize(const OABE_ZP *zp, OABE_ByteString **result) {
    if (!zp || !result) return OABE_ERROR_INVALID_INPUT;
    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)zp;

    *result = oabe_bytestring_new();
    if (!*result) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_ERROR rc = oabe_bytestring_append_byte(*result, OABE_TAG_ZP);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    int len = bn_size_bin(impl->value);
    rc = oabe_bytestring_pack32(*result, (uint32_t)len);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    uint8_t *buf = (uint8_t *)oabe_malloc(len);
    if (!buf) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    bn_write_bin(buf, len, impl->value);
    rc = oabe_bytestring_append_data(*result, buf, len);
    oabe_free(buf);

    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
    }

    return rc;
}

OABE_ERROR oabe_zp_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_ZP **zp) {
    if (!group || !input || !zp) return OABE_ERROR_INVALID_INPUT;

    size_t index = 0;
    uint8_t tag;
    OABE_ERROR rc = oabe_bytestring_unpack8(input, &index, &tag);
    if (rc != OABE_SUCCESS) return rc;
    if (tag != OABE_TAG_ZP) return OABE_ERROR_DESERIALIZATION_FAILED;

    uint32_t len;
    rc = oabe_bytestring_unpack32(input, &index, &len);
    if (rc != OABE_SUCCESS) return rc;

    if (oabe_bytestring_get_size(input) < index + len) return OABE_ERROR_DESERIALIZATION_FAILED;

    *zp = oabe_zp_new(group);
    if (!*zp) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_ZP_Impl *impl = (OABE_ZP_Impl *)*zp;
    const uint8_t *data = oabe_bytestring_get_const_ptr(input) + index;
    bn_read_bin(impl->value, data, (int)len);

    return OABE_SUCCESS;
}

/*============================================================================
 * G1 Implementation
 *============================================================================*/

static void oabe_g1_destroy(void *ptr) {
    OABE_G1_Impl *g1 = (OABE_G1_Impl *)ptr;
    if (g1) {
        g1_free(g1->point);
        if (g1->group) oabe_group_free(g1->group);
        oabe_free(g1);
    }
}

OABE_G1* oabe_g1_new(OABE_GroupHandle group) {
    if (!group) return NULL;

    OABE_G1_Impl *g1 = (OABE_G1_Impl *)oabe_malloc(sizeof(OABE_G1_Impl));
    if (!g1) return NULL;

    g1->base.ref_count = 1;
    g1->base.vtable = &g_g1_vtable;
    g1->group = group;
    OABE_ADDREF(group);

    g1_null(g1->point);
    g1_new(g1->point);
    g1_set_infty(g1->point);

    return (OABE_G1 *)g1;
}

void oabe_g1_free(OABE_G1 *g1) {
    if (g1) {
        OABE_DEREF(g1);
    }
}

OABE_G1* oabe_g1_clone(const OABE_G1 *g1) {
    if (!g1) return NULL;

    OABE_G1_Impl *impl = (OABE_G1_Impl *)g1;
    OABE_G1_Impl *clone = (OABE_G1_Impl *)oabe_g1_new(impl->group);
    if (!clone) return NULL;

    g1_copy(clone->point, impl->point);
    return (OABE_G1 *)clone;
}

OABE_ERROR oabe_g1_set_identity(OABE_G1 *g1) {
    if (!g1) return OABE_ERROR_INVALID_INPUT;
    OABE_G1_Impl *impl = (OABE_G1_Impl *)g1;
    g1_set_infty(impl->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g1_set_generator(OABE_G1 *g1) {
    if (!g1) return OABE_ERROR_INVALID_INPUT;
    OABE_G1_Impl *impl = (OABE_G1_Impl *)g1;
    OABE_Group_Impl *g = (OABE_Group_Impl *)impl->group;
    g1_copy(impl->point, g->g1_gen);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g1_random(OABE_G1 *g1, OABE_RNGHandle rng) {
    if (!g1) return OABE_ERROR_INVALID_INPUT;
    (void)rng;
    OABE_G1_Impl *impl = (OABE_G1_Impl *)g1;
    g1_rand(impl->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g1_hash(OABE_G1 *g1, const uint8_t *msg, size_t len) {
    if (!g1 || !msg || len == 0) return OABE_ERROR_INVALID_INPUT;
    OABE_G1_Impl *impl = (OABE_G1_Impl *)g1;
    g1_map(impl->point, msg, len);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g1_add(OABE_G1 *result, const OABE_G1 *a, const OABE_G1 *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_G1_Impl *r = (OABE_G1_Impl *)result;
    OABE_G1_Impl *ra = (OABE_G1_Impl *)a;
    OABE_G1_Impl *rb = (OABE_G1_Impl *)b;
    g1_add(r->point, ra->point, rb->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g1_sub(OABE_G1 *result, const OABE_G1 *a, const OABE_G1 *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_G1_Impl *r = (OABE_G1_Impl *)result;
    OABE_G1_Impl *ra = (OABE_G1_Impl *)a;
    OABE_G1_Impl *rb = (OABE_G1_Impl *)b;
    g1_sub(r->point, ra->point, rb->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g1_mul_scalar(OABE_G1 *result, const OABE_G1 *a, const OABE_ZP *scalar) {
    if (!result || !a || !scalar) return OABE_ERROR_INVALID_INPUT;
    OABE_G1_Impl *r = (OABE_G1_Impl *)result;
    OABE_G1_Impl *ra = (OABE_G1_Impl *)a;
    OABE_ZP_Impl *s = (OABE_ZP_Impl *)scalar;
    g1_mul(r->point, ra->point, s->value);
    return OABE_SUCCESS;
}

bool oabe_g1_equals(const OABE_G1 *a, const OABE_G1 *b) {
    if (!a || !b) return false;
    OABE_G1_Impl *ra = (OABE_G1_Impl *)a;
    OABE_G1_Impl *rb = (OABE_G1_Impl *)b;
    return g1_cmp(ra->point, rb->point) == RLC_EQ;
}

bool oabe_g1_is_identity(const OABE_G1 *g1) {
    if (!g1) return false;
    OABE_G1_Impl *impl = (OABE_G1_Impl *)g1;
    return g1_is_infty(impl->point);
}

OABE_ERROR oabe_g1_serialize(const OABE_G1 *g1, OABE_ByteString **result) {
    if (!g1 || !result) return OABE_ERROR_INVALID_INPUT;
    OABE_G1_Impl *impl = (OABE_G1_Impl *)g1;

    *result = oabe_bytestring_new();
    if (!*result) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_ERROR rc = oabe_bytestring_append_byte(*result, OABE_TAG_G1);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    int len = g1_size_bin(impl->point, 1);
    rc = oabe_bytestring_pack32(*result, (uint32_t)len);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    uint8_t *buf = (uint8_t *)oabe_malloc(len);
    if (!buf) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    g1_write_bin(buf, len, impl->point, 1);
    rc = oabe_bytestring_append_data(*result, buf, len);
    oabe_free(buf);

    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
    }

    return rc;
}

OABE_ERROR oabe_g1_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_G1 **g1) {
    if (!group || !input || !g1) return OABE_ERROR_INVALID_INPUT;

    size_t index = 0;
    uint8_t tag;
    OABE_ERROR rc = oabe_bytestring_unpack8(input, &index, &tag);
    if (rc != OABE_SUCCESS) return rc;
    if (tag != OABE_TAG_G1) return OABE_ERROR_DESERIALIZATION_FAILED;

    uint32_t len;
    rc = oabe_bytestring_unpack32(input, &index, &len);
    if (rc != OABE_SUCCESS) return rc;

    if (oabe_bytestring_get_size(input) < index + len) return OABE_ERROR_DESERIALIZATION_FAILED;

    *g1 = oabe_g1_new(group);
    if (!*g1) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_G1_Impl *impl = (OABE_G1_Impl *)*g1;
    const uint8_t *data = oabe_bytestring_get_const_ptr(input) + index;
    g1_read_bin(impl->point, data, len);

    return OABE_SUCCESS;
}

/*============================================================================
 * G2 Implementation
 *============================================================================*/

static void oabe_g2_destroy(void *ptr) {
    OABE_G2_Impl *g2 = (OABE_G2_Impl *)ptr;
    if (g2) {
        g2_free(g2->point);
        if (g2->group) oabe_group_free(g2->group);
        oabe_free(g2);
    }
}

OABE_G2* oabe_g2_new(OABE_GroupHandle group) {
    if (!group) return NULL;

    OABE_G2_Impl *g2 = (OABE_G2_Impl *)oabe_malloc(sizeof(OABE_G2_Impl));
    if (!g2) return NULL;

    g2->base.ref_count = 1;
    g2->base.vtable = &g_g2_vtable;
    g2->group = group;
    OABE_ADDREF(group);

    g2_null(g2->point);
    g2_new(g2->point);
    g2_set_infty(g2->point);

    return (OABE_G2 *)g2;
}

void oabe_g2_free(OABE_G2 *g2) {
    if (g2) {
        OABE_DEREF(g2);
    }
}

OABE_G2* oabe_g2_clone(const OABE_G2 *g2) {
    if (!g2) return NULL;

    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    OABE_G2_Impl *clone = (OABE_G2_Impl *)oabe_g2_new(impl->group);
    if (!clone) return NULL;

    g2_copy(clone->point, impl->point);
    return (OABE_G2 *)clone;
}

OABE_ERROR oabe_g2_set_identity(OABE_G2 *g2) {
    if (!g2) return OABE_ERROR_INVALID_INPUT;
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    g2_set_infty(impl->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g2_set_generator(OABE_G2 *g2) {
    if (!g2) return OABE_ERROR_INVALID_INPUT;
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    OABE_Group_Impl *g = (OABE_Group_Impl *)impl->group;
    g2_copy(impl->point, g->g2_gen);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g2_random(OABE_G2 *g2, OABE_RNGHandle rng) {
    if (!g2) return OABE_ERROR_INVALID_INPUT;
    (void)rng;
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    g2_rand(impl->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g2_add(OABE_G2 *result, const OABE_G2 *a, const OABE_G2 *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_G2_Impl *r = (OABE_G2_Impl *)result;
    OABE_G2_Impl *ra = (OABE_G2_Impl *)a;
    OABE_G2_Impl *rb = (OABE_G2_Impl *)b;
    g2_add(r->point, ra->point, rb->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g2_sub(OABE_G2 *result, const OABE_G2 *a, const OABE_G2 *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_G2_Impl *r = (OABE_G2_Impl *)result;
    OABE_G2_Impl *ra = (OABE_G2_Impl *)a;
    OABE_G2_Impl *rb = (OABE_G2_Impl *)b;
    g2_sub(r->point, ra->point, rb->point);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g2_mul_scalar(OABE_G2 *result, const OABE_G2 *a, const OABE_ZP *scalar) {
    if (!result || !a || !scalar) return OABE_ERROR_INVALID_INPUT;
    OABE_G2_Impl *r = (OABE_G2_Impl *)result;
    OABE_G2_Impl *ra = (OABE_G2_Impl *)a;
    OABE_ZP_Impl *s = (OABE_ZP_Impl *)scalar;
    g2_mul(r->point, ra->point, s->value);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_g2_hash(OABE_G2 *g2, const uint8_t *msg, size_t len) {
    if (!g2 || !msg || len == 0) return OABE_ERROR_INVALID_INPUT;
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    g2_map(impl->point, msg, len);
    return OABE_SUCCESS;
}

bool oabe_g2_equals(const OABE_G2 *a, const OABE_G2 *b) {
    if (!a || !b) return false;
    OABE_G2_Impl *ra = (OABE_G2_Impl *)a;
    OABE_G2_Impl *rb = (OABE_G2_Impl *)b;
    return g2_cmp(ra->point, rb->point) == RLC_EQ;
}

bool oabe_g2_is_identity(const OABE_G2 *g2) {
    if (!g2) return false;
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;
    return g2_is_infty(impl->point);
}

OABE_ERROR oabe_g2_serialize(const OABE_G2 *g2, OABE_ByteString **result) {
    if (!g2 || !result) return OABE_ERROR_INVALID_INPUT;
    OABE_G2_Impl *impl = (OABE_G2_Impl *)g2;

    *result = oabe_bytestring_new();
    if (!*result) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_ERROR rc = oabe_bytestring_append_byte(*result, OABE_TAG_G2);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    int len = g2_size_bin(impl->point, 1);
    rc = oabe_bytestring_pack32(*result, (uint32_t)len);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    uint8_t *buf = (uint8_t *)oabe_malloc(len);
    if (!buf) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    g2_write_bin(buf, len, impl->point, 1);
    rc = oabe_bytestring_append_data(*result, buf, len);
    oabe_free(buf);

    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
    }

    return rc;
}

OABE_ERROR oabe_g2_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_G2 **g2) {
    if (!group || !input || !g2) return OABE_ERROR_INVALID_INPUT;

    size_t index = 0;
    uint8_t tag;
    OABE_ERROR rc = oabe_bytestring_unpack8(input, &index, &tag);
    if (rc != OABE_SUCCESS) return rc;
    if (tag != OABE_TAG_G2) return OABE_ERROR_DESERIALIZATION_FAILED;

    uint32_t len;
    rc = oabe_bytestring_unpack32(input, &index, &len);
    if (rc != OABE_SUCCESS) return rc;

    if (oabe_bytestring_get_size(input) < index + len) return OABE_ERROR_DESERIALIZATION_FAILED;

    *g2 = oabe_g2_new(group);
    if (!*g2) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_G2_Impl *impl = (OABE_G2_Impl *)*g2;
    const uint8_t *data = oabe_bytestring_get_const_ptr(input) + index;
    g2_read_bin(impl->point, data, len);

    return OABE_SUCCESS;
}

/*============================================================================
 * GT Implementation
 *============================================================================*/

static void oabe_gt_destroy(void *ptr) {
    OABE_GT_Impl *gt = (OABE_GT_Impl *)ptr;
    if (gt) {
        gt_free(gt->value);
        if (gt->group) oabe_group_free(gt->group);
        oabe_free(gt);
    }
}

OABE_GT* oabe_gt_new(OABE_GroupHandle group) {
    if (!group) return NULL;

    OABE_GT_Impl *gt = (OABE_GT_Impl *)oabe_malloc(sizeof(OABE_GT_Impl));
    if (!gt) return NULL;

    gt->base.ref_count = 1;
    gt->base.vtable = &g_gt_vtable;
    gt->group = group;
    OABE_ADDREF(group);

    gt_null(gt->value);
    gt_new(gt->value);
    gt_set_unity(gt->value);

    return (OABE_GT *)gt;
}

void oabe_gt_free(OABE_GT *gt) {
    if (gt) {
        OABE_DEREF(gt);
    }
}

OABE_GT* oabe_gt_clone(const OABE_GT *gt) {
    if (!gt) return NULL;

    OABE_GT_Impl *impl = (OABE_GT_Impl *)gt;
    OABE_GT_Impl *clone = (OABE_GT_Impl *)oabe_gt_new(impl->group);
    if (!clone) return NULL;

    gt_copy(clone->value, impl->value);
    return (OABE_GT *)clone;
}

OABE_ERROR oabe_gt_set_identity(OABE_GT *gt) {
    if (!gt) return OABE_ERROR_INVALID_INPUT;
    OABE_GT_Impl *impl = (OABE_GT_Impl *)gt;
    gt_set_unity(impl->value);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_gt_mul(OABE_GT *result, const OABE_GT *a, const OABE_GT *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_GT_Impl *r = (OABE_GT_Impl *)result;
    OABE_GT_Impl *ra = (OABE_GT_Impl *)a;
    OABE_GT_Impl *rb = (OABE_GT_Impl *)b;
    gt_mul(r->value, ra->value, rb->value);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_gt_div(OABE_GT *result, const OABE_GT *a, const OABE_GT *b) {
    if (!result || !a || !b) return OABE_ERROR_INVALID_INPUT;
    OABE_GT_Impl *r = (OABE_GT_Impl *)result;
    OABE_GT_Impl *ra = (OABE_GT_Impl *)a;
    OABE_GT_Impl *rb = (OABE_GT_Impl *)b;

    gt_t inv;
    gt_null(inv);
    gt_new(inv);
    gt_inv(inv, rb->value);
    gt_mul(r->value, ra->value, inv);
    gt_free(inv);
    return OABE_SUCCESS;
}

OABE_ERROR oabe_gt_exp(OABE_GT *result, const OABE_GT *base, const OABE_ZP *exp) {
    if (!result || !base || !exp) return OABE_ERROR_INVALID_INPUT;
    OABE_GT_Impl *r = (OABE_GT_Impl *)result;
    OABE_GT_Impl *rb = (OABE_GT_Impl *)base;
    OABE_ZP_Impl *e = (OABE_ZP_Impl *)exp;
    gt_exp(r->value, rb->value, e->value);
    return OABE_SUCCESS;
}

bool oabe_gt_equals(const OABE_GT *a, const OABE_GT *b) {
    if (!a || !b) return false;
    OABE_GT_Impl *ra = (OABE_GT_Impl *)a;
    OABE_GT_Impl *rb = (OABE_GT_Impl *)b;
    return gt_cmp(ra->value, rb->value) == RLC_EQ;
}

bool oabe_gt_is_identity(const OABE_GT *gt) {
    if (!gt) return false;
    OABE_GT_Impl *impl = (OABE_GT_Impl *)gt;
    return gt_is_unity(impl->value);
}

OABE_ERROR oabe_gt_serialize(const OABE_GT *gt, OABE_ByteString **result) {
    if (!gt || !result) return OABE_ERROR_INVALID_INPUT;
    OABE_GT_Impl *impl = (OABE_GT_Impl *)gt;

    *result = oabe_bytestring_new();
    if (!*result) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_ERROR rc = oabe_bytestring_append_byte(*result, OABE_TAG_GT);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    int len = gt_size_bin(impl->value, 1);
    rc = oabe_bytestring_pack32(*result, (uint32_t)len);
    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return rc;
    }

    uint8_t *buf = (uint8_t *)oabe_malloc(len);
    if (!buf) {
        oabe_bytestring_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    gt_write_bin(buf, len, impl->value, 1);
    rc = oabe_bytestring_append_data(*result, buf, len);
    oabe_free(buf);

    if (rc != OABE_SUCCESS) {
        oabe_bytestring_free(*result);
        *result = NULL;
    }

    return rc;
}

OABE_ERROR oabe_gt_deserialize(OABE_GroupHandle group, const OABE_ByteString *input, OABE_GT **gt) {
    if (!group || !input || !gt) return OABE_ERROR_INVALID_INPUT;

    size_t index = 0;
    uint8_t tag;
    OABE_ERROR rc = oabe_bytestring_unpack8(input, &index, &tag);
    if (rc != OABE_SUCCESS) return rc;
    if (tag != OABE_TAG_GT) return OABE_ERROR_DESERIALIZATION_FAILED;

    uint32_t len;
    rc = oabe_bytestring_unpack32(input, &index, &len);
    if (rc != OABE_SUCCESS) return rc;

    if (oabe_bytestring_get_size(input) < index + len) return OABE_ERROR_DESERIALIZATION_FAILED;

    *gt = oabe_gt_new(group);
    if (!*gt) return OABE_ERROR_OUT_OF_MEMORY;

    OABE_GT_Impl *impl = (OABE_GT_Impl *)*gt;
    const uint8_t *data = oabe_bytestring_get_const_ptr(input) + index;
    gt_read_bin(impl->value, data, len);

    return OABE_SUCCESS;
}

/*============================================================================
 * Pairing
 *============================================================================*/

OABE_ERROR oabe_pairing(OABE_GT *result, const OABE_G1 *g1, const OABE_G2 *g2) {
    if (!result || !g1 || !g2) return OABE_ERROR_INVALID_INPUT;
    OABE_GT_Impl *r = (OABE_GT_Impl *)result;
    OABE_G1_Impl *p1 = (OABE_G1_Impl *)g1;
    OABE_G2_Impl *p2 = (OABE_G2_Impl *)g2;
    pc_map(r->value, p1->point, p2->point);
    return OABE_SUCCESS;
}