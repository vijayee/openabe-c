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
/// \file   oabe_init.h
///
/// \brief  Library initialization for OpenABE C implementation.
///

#ifndef OABE_INIT_H
#define OABE_INIT_H

#include "oabe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Library Initialization
 *============================================================================*/

/**
 * Initialize the OpenABE library.
 * Must be called before using any other library functions.
 * Initializes OpenSSL/RELIC crypto backends.
 * @return OABE_SUCCESS on success, error code on failure
 */
OABE_ERROR oabe_init(void);

/**
 * Initialize the OpenABE library without OpenSSL.
 * Uses RELIC backend only.
 * @return OABE_SUCCESS on success, error code on failure
 */
OABE_ERROR oabe_init_without_openssl(void);

/**
 * Shutdown the OpenABE library.
 * Call when done using the library to release all resources.
 * @return OABE_SUCCESS on success, error code on failure
 */
OABE_ERROR oabe_shutdown(void);

/**
 * Check if the library is initialized.
 * @return true if initialized, false otherwise
 */
bool oabe_is_initialized(void);

/**
 * Assert that the library is initialized (for internal use).
 * Calls oabe_init() if not already initialized.
 * @return OABE_SUCCESS on success, error code on failure
 */
OABE_ERROR oabe_assert_initialized(void);

/**
 * Get the library version.
 * @return Library version number
 */
uint32_t oabe_get_library_version(void);

/**
 * Get the library version string.
 * @return Library version string (e.g., "1.7.0")
 */
const char* oabe_get_library_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* OABE_INIT_H */