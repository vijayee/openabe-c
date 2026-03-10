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
/// \file   oabe_memory.c
///
/// \brief  Memory management implementation for OpenABE C.
///

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include "openabe/oabe_memory.h"

/*============================================================================
 * Memory Allocation Functions
 *============================================================================*/

void* oabe_malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "oabe_malloc: Out of memory allocating %zu bytes\n", size);
    }
    return ptr;
}

void* oabe_calloc(size_t count, size_t size) {
    if (count == 0 || size == 0) {
        return NULL;
    }
    void *ptr = calloc(count, size);
    if (!ptr) {
        fprintf(stderr, "oabe_calloc: Out of memory allocating %zu x %zu bytes\n", count, size);
    }
    return ptr;
}

void* oabe_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        fprintf(stderr, "oabe_realloc: Out of memory reallocating to %zu bytes\n", size);
    }
    return new_ptr;
}

void oabe_free(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

void oabe_zeroize(void *ptr, size_t len) {
    if (ptr && len > 0) {
        /* Use volatile to prevent compiler optimization */
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) {
            *p++ = 0;
        }
    }
}

char* oabe_strdup(const char *str) {
    if (!str) {
        return NULL;
    }
    size_t len = strlen(str) + 1;
    char *new_str = (char *)oabe_malloc(len);
    if (new_str) {
        memcpy(new_str, str, len);
    }
    return new_str;
}

void* oabe_memdup(const void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return NULL;
    }
    void *new_ptr = oabe_malloc(len);
    if (new_ptr) {
        memcpy(new_ptr, ptr, len);
    }
    return new_ptr;
}

/*============================================================================
 * Vector Implementation
 *============================================================================*/

#define OABE_VECTOR_DEFAULT_CAPACITY 8

OABE_Vector* oabe_vector_new(size_t initial_capacity) {
    OABE_Vector *vec = (OABE_Vector *)oabe_malloc(sizeof(OABE_Vector));
    if (!vec) {
        return NULL;
    }

    if (initial_capacity == 0) {
        initial_capacity = OABE_VECTOR_DEFAULT_CAPACITY;
    }

    vec->items = (void **)oabe_calloc(initial_capacity, sizeof(void *));
    if (!vec->items) {
        oabe_free(vec);
        return NULL;
    }

    vec->size = 0;
    vec->capacity = initial_capacity;
    return vec;
}

void oabe_vector_free(OABE_Vector *vec) {
    if (vec) {
        oabe_free(vec->items);
        oabe_free(vec);
    }
}

OABE_ERROR oabe_vector_append(OABE_Vector *vec, void *item) {
    if (!vec) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Grow if needed */
    if (vec->size >= vec->capacity) {
        size_t new_capacity = vec->capacity * 2;
        void **new_items = (void **)oabe_realloc(vec->items, new_capacity * sizeof(void *));
        if (!new_items) {
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        vec->items = new_items;
        vec->capacity = new_capacity;
    }

    vec->items[vec->size++] = item;
    return OABE_SUCCESS;
}

void* oabe_vector_get(const OABE_Vector *vec, size_t index) {
    if (!vec || index >= vec->size) {
        return NULL;
    }
    return vec->items[index];
}

OABE_ERROR oabe_vector_remove(OABE_Vector *vec, size_t index) {
    if (!vec || index >= vec->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }

    /* Shift remaining elements */
    for (size_t i = index; i < vec->size - 1; i++) {
        vec->items[i] = vec->items[i + 1];
    }
    vec->size--;
    return OABE_SUCCESS;
}

void oabe_vector_clear(OABE_Vector *vec) {
    if (vec) {
        vec->size = 0;
    }
}

/*============================================================================
 * String Vector Implementation
 *============================================================================*/

OABE_StringVector* oabe_strvec_new(size_t initial_capacity) {
    OABE_StringVector *vec = (OABE_StringVector *)oabe_malloc(sizeof(OABE_StringVector));
    if (!vec) {
        return NULL;
    }

    if (initial_capacity == 0) {
        initial_capacity = OABE_VECTOR_DEFAULT_CAPACITY;
    }

    vec->items = (char **)oabe_calloc(initial_capacity, sizeof(char *));
    if (!vec->items) {
        oabe_free(vec);
        return NULL;
    }

    vec->size = 0;
    vec->capacity = initial_capacity;
    return vec;
}

void oabe_strvec_free(OABE_StringVector *vec) {
    if (vec) {
        if (vec->items) {
            for (size_t i = 0; i < vec->size; i++) {
                oabe_free(vec->items[i]);
            }
            oabe_free(vec->items);
        }
        oabe_free(vec);
    }
}

OABE_ERROR oabe_strvec_append(OABE_StringVector *vec, const char *str) {
    if (!vec || !str) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Grow if needed */
    if (vec->size >= vec->capacity) {
        size_t new_capacity = vec->capacity * 2;
        char **new_items = (char **)oabe_realloc(vec->items, new_capacity * sizeof(char *));
        if (!new_items) {
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        vec->items = new_items;
        vec->capacity = new_capacity;
    }

    char *str_copy = oabe_strdup(str);
    if (!str_copy) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    vec->items[vec->size++] = str_copy;
    return OABE_SUCCESS;
}

const char* oabe_strvec_get(const OABE_StringVector *vec, size_t index) {
    if (!vec || index >= vec->size) {
        return NULL;
    }
    return vec->items[index];
}

OABE_ERROR oabe_strvec_remove(OABE_StringVector *vec, size_t index) {
    if (!vec || index >= vec->size) {
        return OABE_ERROR_INDEX_OUT_OF_BOUNDS;
    }

    /* Free the string at index */
    oabe_free(vec->items[index]);

    /* Shift remaining elements */
    for (size_t i = index; i < vec->size - 1; i++) {
        vec->items[i] = vec->items[i + 1];
    }
    vec->size--;
    return OABE_SUCCESS;
}

/*============================================================================
 * String Map Implementation
 *============================================================================*/

OABE_StringMap* oabe_strmap_new(size_t initial_capacity) {
    OABE_StringMap *map = (OABE_StringMap *)oabe_malloc(sizeof(OABE_StringMap));
    if (!map) {
        return NULL;
    }

    if (initial_capacity == 0) {
        initial_capacity = OABE_VECTOR_DEFAULT_CAPACITY;
    }

    map->keys = (char **)oabe_calloc(initial_capacity, sizeof(char *));
    if (!map->keys) {
        oabe_free(map);
        return NULL;
    }

    map->values = (void **)oabe_calloc(initial_capacity, sizeof(void *));
    if (!map->values) {
        oabe_free(map->keys);
        oabe_free(map);
        return NULL;
    }

    map->size = 0;
    map->capacity = initial_capacity;
    return map;
}

void oabe_strmap_free(OABE_StringMap *map) {
    if (map) {
        if (map->keys) {
            for (size_t i = 0; i < map->size; i++) {
                oabe_free(map->keys[i]);
            }
            oabe_free(map->keys);
        }
        oabe_free(map->values);
        oabe_free(map);
    }
}

static ssize_t oabe_strmap_find_index(const OABE_StringMap *map, const char *key) {
    for (size_t i = 0; i < map->size; i++) {
        if (strcmp(map->keys[i], key) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

OABE_ERROR oabe_strmap_insert(OABE_StringMap *map, const char *key, void *value) {
    if (!map || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Check if key already exists */
    ssize_t idx = oabe_strmap_find_index(map, key);
    if (idx >= 0) {
        /* Update existing value */
        map->values[idx] = value;
        return OABE_SUCCESS;
    }

    /* Grow if needed */
    if (map->size >= map->capacity) {
        size_t new_capacity = map->capacity * 2;
        char **new_keys = (char **)oabe_realloc(map->keys, new_capacity * sizeof(char *));
        if (!new_keys) {
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        void **new_values = (void **)oabe_realloc(map->values, new_capacity * sizeof(void *));
        if (!new_values) {
            map->keys = new_keys;  /* Rollback not possible, keep old */
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        map->keys = new_keys;
        map->values = new_values;
        map->capacity = new_capacity;
    }

    /* Insert new key-value pair */
    char *key_copy = oabe_strdup(key);
    if (!key_copy) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    map->keys[map->size] = key_copy;
    map->values[map->size] = value;
    map->size++;
    return OABE_SUCCESS;
}

void* oabe_strmap_get(const OABE_StringMap *map, const char *key) {
    if (!map || !key) {
        return NULL;
    }
    ssize_t idx = oabe_strmap_find_index(map, key);
    if (idx >= 0) {
        return map->values[idx];
    }
    return NULL;
}

OABE_ERROR oabe_strmap_remove(OABE_StringMap *map, const char *key) {
    if (!map || !key) {
        return OABE_ERROR_INVALID_INPUT;
    }
    ssize_t idx = oabe_strmap_find_index(map, key);
    if (idx < 0) {
        return OABE_ERROR_ELEMENT_NOT_FOUND;
    }

    /* Free the key */
    oabe_free(map->keys[idx]);

    /* Shift remaining elements */
    for (size_t i = (size_t)idx; i < map->size - 1; i++) {
        map->keys[i] = map->keys[i + 1];
        map->values[i] = map->values[i + 1];
    }
    map->size--;
    return OABE_SUCCESS;
}

bool oabe_strmap_contains(const OABE_StringMap *map, const char *key) {
    if (!map || !key) {
        return false;
    }
    return oabe_strmap_find_index(map, key) >= 0;
}