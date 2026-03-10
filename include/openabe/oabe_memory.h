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
/// \file   oabe_memory.h
///
/// \brief  Memory management and reference counting for OpenABE C implementation.
///
/// \author Matthew Green and J. Ayo Akinyele (original C++), C translation
///

#ifndef OABE_MEMORY_H
#define OABE_MEMORY_H

#include <stdint.h>
#include <stddef.h>
#include "oabe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Object VTable - Virtual function table for polymorphism
 *============================================================================*/

/**
 * Virtual function table for OABE_Object.
 * Each derived type must implement these functions.
 */
typedef struct OABE_ObjectVTable {
    /**
     * Destroy the object and free all resources.
     * @param self Pointer to the object
     */
    void (*destroy)(void *self);

    /**
     * Create a clone of the object.
     * @param self Pointer to the object
     * @return Pointer to cloned object, or NULL on failure
     */
    void* (*clone)(const void *self);

    /**
     * Serialize the object to a ByteString.
     * @param self Pointer to the object
     * @param result Output ByteString to store serialized data
     * @return OABE_SUCCESS or error code
     */
    OABE_ERROR (*serialize)(const void *self, struct OABE_ByteString *result);

    /**
     * Check if two objects are equal.
     * @param self Pointer to this object
     * @param other Pointer to other object
     * @return true if equal, false otherwise
     */
    bool (*is_equal)(const void *self, const void *other);
} OABE_ObjectVTable;

/*============================================================================
 * Base Object Structure
 *============================================================================*/

/**
 * Base object structure with reference counting.
 * All OpenABE objects inherit from this structure by embedding it
 * as the first member.
 */
typedef struct OABE_Object {
    const OABE_ObjectVTable *vtable;  /* Virtual function table */
    volatile uint32_t ref_count;      /* Reference count */
} OABE_Object;

/*============================================================================
 * Memory Management Macros
 *============================================================================*/

/**
 * Initialize an OABE_Object structure.
 * @param obj Pointer to the object
 * @param vt Pointer to the vtable
 */
#define OABE_OBJECT_INIT(obj, vt) \
    do { \
        (obj)->base.vtable = (vt); \
        (obj)->base.ref_count = 1; \
    } while(0)

/**
 * Add a reference to an object.
 * Thread-safe increment of reference count.
 * @param obj Pointer to the object
 */
#define OABE_ADDREF(obj) \
    do { \
        if (obj) { \
            __sync_add_and_fetch(&((OABE_Object*)(obj))->ref_count, 1); \
        } \
    } while(0)

/**
 * Release a reference to an object.
 * If ref_count reaches 0, calls the destroy function.
 * Thread-safe decrement of reference count.
 * @param obj Pointer to the object
 */
#define OABE_DEREF(obj) \
    do { \
        if (obj) { \
            if (__sync_sub_and_fetch(&((OABE_Object*)(obj))->ref_count, 1) == 0) { \
                if (((OABE_Object*)(obj))->vtable && ((OABE_Object*)(obj))->vtable->destroy) { \
                    ((OABE_Object*)(obj))->vtable->destroy(obj); \
                } \
            } \
        } \
    } while(0)

/**
 * Get reference count of an object.
 * @param obj Pointer to the object
 * @return Current reference count
 */
static inline uint32_t oabe_get_refcount(const void *obj) {
    if (!obj) return 0;
    return ((const OABE_Object*)obj)->ref_count;
}

/*============================================================================
 * Memory Allocation Functions
 *============================================================================*/

/**
 * Allocate memory with error checking.
 * @param size Size in bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
void* oabe_malloc(size_t size);

/**
 * Allocate zeroed memory.
 * @param count Number of elements
 * @param size Size of each element
 * @return Pointer to allocated memory, or NULL on failure
 */
void* oabe_calloc(size_t count, size_t size);

/**
 * Reallocate memory.
 * @param ptr Existing pointer (can be NULL)
 * @param size New size in bytes
 * @return Pointer to reallocated memory, or NULL on failure
 */
void* oabe_realloc(void *ptr, size_t size);

/**
 * Free memory.
 * @param ptr Pointer to free (can be NULL)
 */
void oabe_free(void *ptr);

/**
 * Securely zero memory.
 * This function will not be optimized away by the compiler.
 * @param ptr Pointer to memory
 * @param len Length in bytes
 */
void oabe_zeroize(void *ptr, size_t len);

/**
 * Duplicate a string.
 * @param str String to duplicate
 * @return Pointer to duplicated string, or NULL on failure
 */
char* oabe_strdup(const char *str);

/**
 * Duplicate memory.
 * @param ptr Pointer to memory
 * @param len Length in bytes
 * @return Pointer to duplicated memory, or NULL on failure
 */
void* oabe_memdup(const void *ptr, size_t len);

/*============================================================================
 * Vector Types for C
 *============================================================================*/

/**
 * Generic vector structure for storing pointers.
 */
typedef struct OABE_Vector {
    void **items;
    size_t size;
    size_t capacity;
} OABE_Vector;

/**
 * Create a new vector.
 * @param initial_capacity Initial capacity (0 for default)
 * @return Pointer to new vector, or NULL on failure
 */
OABE_Vector* oabe_vector_new(size_t initial_capacity);

/**
 * Free a vector (does not free items).
 * @param vec Vector to free
 */
void oabe_vector_free(OABE_Vector *vec);

/**
 * Append an item to a vector.
 * @param vec Vector
 * @param item Item to append
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_vector_append(OABE_Vector *vec, void *item);

/**
 * Get an item from a vector.
 * @param vec Vector
 * @param index Index
 * @return Item at index, or NULL if out of bounds
 */
void* oabe_vector_get(const OABE_Vector *vec, size_t index);

/**
 * Remove an item from a vector.
 * @param vec Vector
 * @param index Index
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_vector_remove(OABE_Vector *vec, size_t index);

/**
 * Clear a vector (does not free items).
 * @param vec Vector
 */
void oabe_vector_clear(OABE_Vector *vec);

/*============================================================================
 * String Vector Type
 *============================================================================*/

/**
 * Vector structure for storing strings.
 */
typedef struct OABE_StringVector {
    char **items;
    size_t size;
    size_t capacity;
} OABE_StringVector;

/**
 * Create a new string vector.
 * @param initial_capacity Initial capacity (0 for default)
 * @return Pointer to new vector, or NULL on failure
 */
OABE_StringVector* oabe_strvec_new(size_t initial_capacity);

/**
 * Free a string vector (frees all strings and the vector).
 * @param vec Vector to free
 */
void oabe_strvec_free(OABE_StringVector *vec);

/**
 * Append a string to a vector (copies the string).
 * @param vec Vector
 * @param str String to append
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_strvec_append(OABE_StringVector *vec, const char *str);

/**
 * Get a string from a vector.
 * @param vec Vector
 * @param index Index
 * @return String at index, or NULL if out of bounds
 */
const char* oabe_strvec_get(const OABE_StringVector *vec, size_t index);

/**
 * Remove a string from a vector.
 * @param vec Vector
 * @param index Index
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_strvec_remove(OABE_StringVector *vec, size_t index);

/*============================================================================
 * String Map Type
 *============================================================================*/

/**
 * Map structure for string -> pointer mapping.
 */
typedef struct OABE_StringMap {
    char **keys;
    void **values;
    size_t size;
    size_t capacity;
} OABE_StringMap;

/**
 * Create a new string map.
 * @param initial_capacity Initial capacity (0 for default)
 * @return Pointer to new map, or NULL on failure
 */
OABE_StringMap* oabe_strmap_new(size_t initial_capacity);

/**
 * Free a string map (frees all keys but not values).
 * @param map Map to free
 */
void oabe_strmap_free(OABE_StringMap *map);

/**
 * Insert a key-value pair into a map.
 * @param map Map
 * @param key Key (copied)
 * @param value Value
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_strmap_insert(OABE_StringMap *map, const char *key, void *value);

/**
 * Get a value from a map.
 * @param map Map
 * @param key Key
 * @return Value if found, or NULL
 */
void* oabe_strmap_get(const OABE_StringMap *map, const char *key);

/**
 * Remove a key-value pair from a map.
 * @param map Map
 * @param key Key
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_strmap_remove(OABE_StringMap *map, const char *key);

/**
 * Check if a key exists in a map.
 * @param map Map
 * @param key Key
 * @return true if key exists, false otherwise
 */
bool oabe_strmap_contains(const OABE_StringMap *map, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* OABE_MEMORY_H */