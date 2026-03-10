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
/// \file   oabe_init.c
///
/// \brief  Library initialization implementation for OpenABE C.
///

#include <pthread.h>
#include "openabe/oabe_init.h"
#include "openabe/oabe_types.h"
#include "openabe/oabe_memory.h"

/* For crypto backend initialization */
#if defined(BP_WITH_OPENSSL)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#elif defined(WITH_RELIC)
#include <relic.h>
#endif

/*============================================================================
 * Global State
 *============================================================================*/

/* Thread-local initialization state */
static pthread_key_t g_thread_init_key;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;
static volatile bool g_library_initialized = false;
static volatile bool g_using_openssl = false;

/*============================================================================
 * Version Information
 *============================================================================*/

#define OABE_VERSION_MAJOR 1
#define OABE_VERSION_MINOR 7
#define OABE_VERSION_PATCH 0

static const char *g_version_string = "1.7.0";

/*============================================================================
 * Internal Functions
 *============================================================================*/

static void oabe_destroy_thread_state(void *ptr) {
    int *state = (int *)ptr;
    if (state) {
        oabe_free(state);
    }
}

static void oabe_init_keys(void) {
    pthread_key_create(&g_thread_init_key, oabe_destroy_thread_state);
}

static bool oabe_is_thread_initialized(void) {
    pthread_once(&g_init_once, oabe_init_keys);
    int *state = (int *)pthread_getspecific(g_thread_init_key);
    return state != NULL && *state != 0;
}

static OABE_ERROR oabe_init_thread(void) {
    pthread_once(&g_init_once, oabe_init_keys);

    int *state = (int *)pthread_getspecific(g_thread_init_key);
    if (!state) {
        state = (int *)oabe_malloc(sizeof(int));
        if (!state) {
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        *state = 1;
        pthread_setspecific(g_thread_init_key, state);
    }
    return OABE_SUCCESS;
}

static void oabe_shutdown_thread(void) {
    pthread_once(&g_init_once, oabe_init_keys);

    int *state = (int *)pthread_getspecific(g_thread_init_key);
    if (state) {
        oabe_free(state);
        pthread_setspecific(g_thread_init_key, NULL);
    }
}

/*============================================================================
 * Public Functions
 *============================================================================*/

OABE_ERROR oabe_init(void) {
    if (g_library_initialized) {
        return OABE_SUCCESS;
    }

    /* Initialize crypto backend */
#if defined(BP_WITH_OPENSSL)
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Initialize PRNG */
    if (RAND_poll() != 1) {
        return OABE_ERROR_INVALID_RNG;
    }

    g_using_openssl = true;
#elif defined(WITH_RELIC)
    /* Initialize RELIC */
    core_init();
    if (core_get()->code != RLC_OK) {
        core_clean();
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Initialize pairing-friendly curve parameters */
    if (ep_param_set_any_pairf() != RLC_OK) {
        core_clean();
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Initialize PC core for pairing operations */
    pc_core_init();
#else
    #error "No crypto backend defined. Define BP_WITH_OPENSSL or WITH_RELIC"
#endif

    /* Initialize per-thread state */
    OABE_ERROR rc = oabe_init_thread();
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    g_library_initialized = true;
    return OABE_SUCCESS;
}

OABE_ERROR oabe_init_without_openssl(void) {
#if defined(BP_WITH_OPENSSL)
    /* OpenSSL-only build - RELIC not available */
    return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
#elif defined(WITH_RELIC)
    /* Always use RELIC backend */
    if (g_library_initialized) {
        return OABE_SUCCESS;
    }

    /* Initialize RELIC */
    core_init();
    if (core_get()->code != RLC_OK) {
        core_clean();
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Initialize pairing-friendly curve parameters */
    if (ep_param_set_any_pairf() != RLC_OK) {
        core_clean();
        return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
    }

    /* Initialize PC core */
    pc_core_init();

    g_using_openssl = false;

    /* Initialize per-thread state */
    OABE_ERROR rc = oabe_init_thread();
    if (rc != OABE_SUCCESS) {
        return rc;
    }

    g_library_initialized = true;
    return OABE_SUCCESS;
#else
    return OABE_ERROR_LIBRARY_NOT_INITIALIZED;
#endif
}

OABE_ERROR oabe_shutdown(void) {
    if (!g_library_initialized) {
        return OABE_SUCCESS;
    }

    /* Cleanup per-thread state */
    oabe_shutdown_thread();

    /* Cleanup crypto backend */
#if defined(BP_WITH_OPENSSL)
    EVP_cleanup();
    ERR_free_strings();
#elif defined(WITH_RELIC)
    pc_core_clean();
    core_clean();
#endif

    g_library_initialized = false;
    g_using_openssl = false;
    return OABE_SUCCESS;
}

bool oabe_is_initialized(void) {
    return g_library_initialized && oabe_is_thread_initialized();
}

OABE_ERROR oabe_assert_initialized(void) {
    if (!g_library_initialized) {
        return oabe_init();
    }
    if (!oabe_is_thread_initialized()) {
        return oabe_init_thread();
    }
    return OABE_SUCCESS;
}

uint32_t oabe_get_library_version(void) {
    return OABE_LIBRARY_VERSION;
}

const char* oabe_get_library_version_string(void) {
    return g_version_string;
}