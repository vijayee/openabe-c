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
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   oabe_types.c
///
/// \brief  Type conversion utilities implementation.
///

#include <string.h>
#include "openabe/oabe_types.h"

/*============================================================================
 * Curve ID Conversion
 *============================================================================*/

static const struct {
    OABE_CurveID id;
    const char *name;
} g_curve_names[] = {
    { OABE_CURVE_NIST_P256, "NIST_P256" },
    { OABE_CURVE_NIST_P384, "NIST_P384" },
    { OABE_CURVE_NIST_P521, "NIST_P521" },
    { OABE_CURVE_BN_P158, "BN_P158" },
    { OABE_CURVE_BN_P254, "BN_P254" },
    { OABE_CURVE_BN_P256, "BN_P256" },
    { OABE_CURVE_KSS_508, "KSS_508" },
    { OABE_CURVE_BN_P382, "BN_P382" },
    { OABE_CURVE_BN_P638, "BN_P638" },
};

OABE_CurveID oabe_curve_id_from_string(const char *params_id) {
    if (!params_id) return OABE_CURVE_NONE;

    for (size_t i = 0; i < sizeof(g_curve_names) / sizeof(g_curve_names[0]); i++) {
        if (strcmp(params_id, g_curve_names[i].name) == 0) {
            return g_curve_names[i].id;
        }
    }
    return OABE_CURVE_NONE;
}

const char* oabe_curve_id_to_string(OABE_CurveID id) {
    for (size_t i = 0; i < sizeof(g_curve_names) / sizeof(g_curve_names[0]); i++) {
        if (g_curve_names[i].id == id) {
            return g_curve_names[i].name;
        }
    }
    return "UNKNOWN";
}

OABE_CurveID oabe_get_curve_id(uint8_t id) {
    return (OABE_CurveID)id;
}

/*============================================================================
 * Scheme ID Conversion
 *============================================================================*/

static const struct {
    OABE_Scheme scheme;
    const char *name;
} g_scheme_names[] = {
    { OABE_SCHEME_PKSIG_ECDSA, "PKSIG_ECDSA" },
    { OABE_SCHEME_AES_GCM, "AES_GCM" },
    { OABE_SCHEME_PK_OPDH, "PK_OPDH" },
    { OABE_SCHEME_CP_WATERS, "CP_WATERS" },
    { OABE_SCHEME_KP_GPSW, "KP_GPSW" },
    { OABE_SCHEME_CP_WATERS_CCA, "CP_WATERS_CCA" },
    { OABE_SCHEME_KP_GPSW_CCA, "KP_GPSW_CCA" },
};

static const struct {
    OABE_Scheme scheme;
    const char *short_name;
} g_scheme_short_names[] = {
    { OABE_SCHEME_PKSIG_ECDSA, OABE_EC_DSA_STR },
    { OABE_SCHEME_PK_OPDH, OABE_PK_ENC_STR },
    { OABE_SCHEME_CP_WATERS, OABE_CP_ABE_STR },
    { OABE_SCHEME_KP_GPSW, OABE_KP_ABE_STR },
};

OABE_Scheme oabe_scheme_from_string(const char *id) {
    if (!id) return OABE_SCHEME_NONE;

    /* Check long names */
    for (size_t i = 0; i < sizeof(g_scheme_names) / sizeof(g_scheme_names[0]); i++) {
        if (strcmp(id, g_scheme_names[i].name) == 0) {
            return g_scheme_names[i].scheme;
        }
    }

    /* Check short names */
    for (size_t i = 0; i < sizeof(g_scheme_short_names) / sizeof(g_scheme_short_names[0]); i++) {
        if (strcmp(id, g_scheme_short_names[i].short_name) == 0) {
            return g_scheme_short_names[i].scheme;
        }
    }

    return OABE_SCHEME_NONE;
}

const char* oabe_scheme_to_string(OABE_Scheme scheme) {
    for (size_t i = 0; i < sizeof(g_scheme_names) / sizeof(g_scheme_names[0]); i++) {
        if (g_scheme_names[i].scheme == scheme) {
            return g_scheme_names[i].name;
        }
    }
    return "UNKNOWN";
}

OABE_Scheme oabe_get_scheme_id(uint8_t id) {
    return (OABE_Scheme)id;
}