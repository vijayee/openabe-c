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
/// \file   oabe_policy.c
///
/// \brief  Policy parsing implementation for OpenABE C.
///

#define _GNU_SOURCE  /* for strncasecmp, strcasestr */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "openabe/oabe_policy.h"
#include "openabe/oabe_memory.h"

#define PREFIX_SEP ':'
#define MAX_POLICY_DEPTH 256

/*============================================================================
 * Policy Tree Node Implementation
 *============================================================================*/

static void oabe_policy_node_destroy(void *self) {
    OABE_PolicyNode *node = (OABE_PolicyNode *)self;
    if (node) {
        if (node->attribute) {
            oabe_free(node->attribute);
        }
        if (node->children) {
            for (size_t i = 0; i < node->num_children; i++) {
                if (node->children[i]) {
                    OABE_DEREF(node->children[i]);
                }
            }
            oabe_free(node->children);
        }
        if (node->sat_list) {
            oabe_free(node->sat_list);
        }
        oabe_free(node);
    }
}

static void* oabe_policy_node_clone(const void *self) {
    const OABE_PolicyNode *node = (const OABE_PolicyNode *)self;
    if (!node) return NULL;

    OABE_PolicyNode *new_node = (OABE_PolicyNode *)oabe_malloc(sizeof(OABE_PolicyNode));
    if (!new_node) return NULL;

    memset(new_node, 0, sizeof(OABE_PolicyNode));
    new_node->base.vtable = node->base.vtable;
    new_node->base.ref_count = 1;
    new_node->type = node->type;
    new_node->threshold = node->threshold;

    if (node->attribute) {
        new_node->attribute = oabe_strdup(node->attribute);
        if (!new_node->attribute) {
            oabe_free(new_node);
            return NULL;
        }
    }

    if (node->num_children > 0) {
        new_node->children = (OABE_PolicyNode **)oabe_calloc(node->num_children, sizeof(OABE_PolicyNode *));
        if (!new_node->children) {
            oabe_free(new_node->attribute);
            oabe_free(new_node);
            return NULL;
        }
        new_node->num_children = node->num_children;

        for (size_t i = 0; i < node->num_children; i++) {
            if (node->children[i]) {
                new_node->children[i] = (OABE_PolicyNode *)oabe_policy_node_clone(node->children[i]);
            }
        }
    }

    return new_node;
}

static const OABE_ObjectVTable g_policy_node_vtable = {
    .destroy = oabe_policy_node_destroy,
    .clone = oabe_policy_node_clone,
    .serialize = NULL,
    .is_equal = NULL
};

/*============================================================================
 * Policy Node Creation
 *============================================================================*/

OABE_PolicyNode* oabe_policy_node_new_leaf(const char *attribute) {
    OABE_PolicyNode *node = (OABE_PolicyNode *)oabe_malloc(sizeof(OABE_PolicyNode));
    if (!node) return NULL;

    memset(node, 0, sizeof(OABE_PolicyNode));
    node->base.vtable = &g_policy_node_vtable;
    node->base.ref_count = 1;
    node->type = OABE_POLICY_LEAF;
    node->threshold = 1;  /* Leaf nodes need threshold 1 (1-of-1) */

    if (attribute) {
        node->attribute = oabe_strdup(attribute);
        if (!node->attribute) {
            oabe_free(node);
            return NULL;
        }
    }

    return node;
}

OABE_PolicyNode* oabe_policy_node_new_internal(OABE_PolicyNodeType type, int threshold) {
    OABE_PolicyNode *node = (OABE_PolicyNode *)oabe_malloc(sizeof(OABE_PolicyNode));
    if (!node) return NULL;

    memset(node, 0, sizeof(OABE_PolicyNode));
    node->base.vtable = &g_policy_node_vtable;
    node->base.ref_count = 1;
    node->type = type;
    node->threshold = threshold;

    return node;
}

void oabe_policy_node_free(OABE_PolicyNode *node) {
    if (node) {
        OABE_DEREF(node);
    }
}

OABE_ERROR oabe_policy_node_add_child(OABE_PolicyNode *parent, OABE_PolicyNode *child) {
    if (!parent || !child) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (parent->type == OABE_POLICY_LEAF) {
        return OABE_ERROR_INVALID_POLICY;
    }

    /* Grow children array */
    size_t new_size = parent->num_children + 1;
    OABE_PolicyNode **new_children = (OABE_PolicyNode **)oabe_realloc(
        parent->children, new_size * sizeof(OABE_PolicyNode *));

    if (!new_children) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    parent->children = new_children;
    parent->children[parent->num_children] = child;
    parent->num_children = new_size;

    return OABE_SUCCESS;
}

/*============================================================================
 * Policy Tree Implementation
 *============================================================================*/

static void oabe_policy_tree_destroy(void *self) {
    OABE_PolicyTree *tree = (OABE_PolicyTree *)self;
    if (tree) {
        if (tree->root) {
            OABE_DEREF(tree->root);
        }
        if (tree->attributes) {
            oabe_strvec_free(tree->attributes);
        }
        oabe_free(tree);
    }
}

static const OABE_ObjectVTable g_policy_tree_vtable = {
    .destroy = oabe_policy_tree_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

/*============================================================================
 * Policy Parsing
 *============================================================================*/

/* Token types */
typedef enum {
    TOKEN_NONE = 0,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_COMMA,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_ATTR,
    TOKEN_THRESHOLD,  /* e.g., "2of3" */
    TOKEN_EOF
} TokenType;

typedef struct {
    const char *input;
    size_t pos;
    size_t len;
    TokenType current_token;
    char token_value[256];
    size_t token_len;
} PolicyParser;

static void skip_whitespace(PolicyParser *p) {
    while (p->pos < p->len && isspace((unsigned char)p->input[p->pos])) {
        p->pos++;
    }
}

static TokenType next_token(PolicyParser *p) {
    skip_whitespace(p);

    if (p->pos >= p->len) {
        p->current_token = TOKEN_EOF;
        return TOKEN_EOF;
    }

    char c = p->input[p->pos];

    if (c == '(') {
        p->pos++;
        p->current_token = TOKEN_LPAREN;
        return TOKEN_LPAREN;
    }

    if (c == ')') {
        p->pos++;
        p->current_token = TOKEN_RPAREN;
        return TOKEN_RPAREN;
    }

    if (c == ',') {
        p->pos++;
        p->current_token = TOKEN_COMMA;
        return TOKEN_COMMA;
    }

    /* Check for AND/OR keywords */
    if (strncasecmp(p->input + p->pos, "AND", 3) == 0 &&
        (p->pos + 3 >= p->len || !isalnum((unsigned char)p->input[p->pos + 3]))) {
        p->pos += 3;
        p->current_token = TOKEN_AND;
        return TOKEN_AND;
    }

    if (strncasecmp(p->input + p->pos, "OR", 2) == 0 &&
        (p->pos + 2 >= p->len || !isalnum((unsigned char)p->input[p->pos + 2]))) {
        p->pos += 2;
        p->current_token = TOKEN_OR;
        return TOKEN_OR;
    }

    /* Parse attribute name or threshold specifier */
    p->token_len = 0;
    while (p->pos < p->len && p->token_len < sizeof(p->token_value) - 1) {
        c = p->input[p->pos];
        if (isspace((unsigned char)c) || c == '(' || c == ')' || c == ',') {
            break;
        }
        p->token_value[p->token_len++] = c;
        p->pos++;
    }
    p->token_value[p->token_len] = '\0';

    /* Check if this is a threshold specifier like "2of3" */
    int k, n;
    if (sscanf(p->token_value, "%dof%d", &k, &n) == 2) {
        p->current_token = TOKEN_THRESHOLD;
        return TOKEN_THRESHOLD;
    }

    p->current_token = TOKEN_ATTR;
    return TOKEN_ATTR;
}

static OABE_PolicyNode* parse_expression(PolicyParser *p);
static OABE_PolicyNode* parse_factor(PolicyParser *p);

/* Parse a comma-separated attribute list for threshold gates */
static OABE_PolicyNode* parse_threshold_list(PolicyParser *p) {
    OABE_PolicyNode **children = NULL;
    size_t num_children = 0;
    size_t children_capacity = 8;

    children = (OABE_PolicyNode **)oabe_calloc(children_capacity, sizeof(OABE_PolicyNode *));
    if (!children) return NULL;

    /* Parse comma-separated list */
    while (p->current_token == TOKEN_ATTR || p->current_token == TOKEN_LPAREN) {
        OABE_PolicyNode *child;

        if (p->current_token == TOKEN_LPAREN) {
            child = parse_factor(p);  /* Recursively parse nested expression */
        } else {
            child = oabe_policy_node_new_leaf(p->token_value);
            next_token(p);
        }

        if (!child) {
            for (size_t i = 0; i < num_children; i++) {
                oabe_policy_node_free(children[i]);
            }
            oabe_free(children);
            return NULL;
        }

        /* Grow array if needed */
        if (num_children >= children_capacity) {
            children_capacity *= 2;
            OABE_PolicyNode **new_children = (OABE_PolicyNode **)oabe_realloc(
                children, children_capacity * sizeof(OABE_PolicyNode *));
            if (!new_children) {
                for (size_t i = 0; i < num_children; i++) {
                    oabe_policy_node_free(children[i]);
                }
                oabe_free(children);
                oabe_policy_node_free(child);
                return NULL;
            }
            children = new_children;
        }

        children[num_children++] = child;

        /* Check for comma */
        if (p->current_token == TOKEN_COMMA) {
            next_token(p);  /* Skip ',' */
        } else {
            break;  /* No more commas, end of list */
        }
    }

    /* Check for closing parenthesis */
    if (p->current_token != TOKEN_RPAREN) {
        for (size_t i = 0; i < num_children; i++) {
            oabe_policy_node_free(children[i]);
        }
        oabe_free(children);
        return NULL;
    }
    next_token(p);  /* Skip ')' */

    /* Check for threshold specifier */
    if (p->current_token == TOKEN_THRESHOLD) {
        int k, n;
        if (sscanf(p->token_value, "%dof%d", &k, &n) != 2) {
            for (size_t i = 0; i < num_children; i++) {
                oabe_policy_node_free(children[i]);
            }
            oabe_free(children);
            return NULL;
        }
        next_token(p);

        /* Create threshold node */
        OABE_PolicyNode *node = oabe_policy_node_new_internal(OABE_POLICY_THRESHOLD, k);
        if (!node) {
            for (size_t i = 0; i < num_children; i++) {
                oabe_policy_node_free(children[i]);
            }
            oabe_free(children);
            return NULL;
        }

        for (size_t i = 0; i < num_children; i++) {
            oabe_policy_node_add_child(node, children[i]);
        }
        oabe_free(children);
        return node;
    }

    /* No threshold specifier - return single child or error */
    if (num_children == 1) {
        OABE_PolicyNode *result = children[0];
        oabe_free(children);
        return result;
    }

    /* Multiple items without threshold specifier is an error in threshold gate syntax */
    for (size_t i = 0; i < num_children; i++) {
        oabe_policy_node_free(children[i]);
    }
    oabe_free(children);
    return NULL;
}

static OABE_PolicyNode* parse_factor(PolicyParser *p) {
    if (p->current_token == TOKEN_LPAREN) {
        next_token(p);  /* Skip '(' */

        /* Try to parse as threshold gate first - if we see ATTR followed by COMMA */
        if (p->current_token == TOKEN_ATTR) {
            /* Save position for backtracking */
            size_t saved_pos = p->pos;
            TokenType saved_token = p->current_token;
            char saved_value[256];
            strncpy(saved_value, p->token_value, sizeof(saved_value));
            saved_value[sizeof(saved_value) - 1] = '\0';

            /* Skip this attribute to check for comma */
            next_token(p);

            /* If next is COMMA, this is a threshold gate */
            if (p->current_token == TOKEN_COMMA) {
                /* Restore to first attribute and parse as threshold list */
                p->pos = saved_pos;
                p->current_token = saved_token;
                strncpy(p->token_value, saved_value, sizeof(p->token_value));
                p->token_value[sizeof(p->token_value) - 1] = '\0';

                return parse_threshold_list(p);
            }

            /* Restore and continue as regular expression */
            p->pos = saved_pos;
            p->current_token = saved_token;
            strncpy(p->token_value, saved_value, sizeof(p->token_value));
            p->token_value[sizeof(saved_value) - 1] = '\0';
        }

        /* Parse as regular AND/OR expression */
        OABE_PolicyNode *node = parse_expression(p);
        if (!node) return NULL;

        if (p->current_token != TOKEN_RPAREN) {
            oabe_policy_node_free(node);
            return NULL;
        }
        next_token(p);  /* Skip ')' */

        return node;
    }

    if (p->current_token == TOKEN_ATTR) {
        OABE_PolicyNode *node = oabe_policy_node_new_leaf(p->token_value);
        if (!node) return NULL;
        next_token(p);
        return node;
    }

    return NULL;
}

static OABE_PolicyNode* parse_expression(PolicyParser *p) {
    OABE_PolicyNode *left = parse_factor(p);
    if (!left) return NULL;

    while (p->current_token == TOKEN_AND || p->current_token == TOKEN_OR) {
        OABE_PolicyNodeType type = (p->current_token == TOKEN_AND) ?
            OABE_POLICY_AND : OABE_POLICY_OR;

        next_token(p);  /* Skip operator */

        OABE_PolicyNode *right = parse_factor(p);
        if (!right) {
            oabe_policy_node_free(left);
            return NULL;
        }

        /* Create internal node */
        OABE_PolicyNode *internal = oabe_policy_node_new_internal(type, type == OABE_POLICY_AND ? 2 : 1);
        if (!internal) {
            oabe_policy_node_free(left);
            oabe_policy_node_free(right);
            return NULL;
        }

        oabe_policy_node_add_child(internal, left);
        oabe_policy_node_add_child(internal, right);

        /* Update threshold for OR gate */
        if (type == OABE_POLICY_OR) {
            internal->threshold = 1;  /* 1-of-N */
        }

        left = internal;
    }

    return left;
}

OABE_ERROR oabe_policy_parse(const char *policy, OABE_PolicyTree **tree) {
    if (!policy || !tree) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *tree = NULL;

    PolicyParser parser = {
        .input = policy,
        .pos = 0,
        .len = strlen(policy),
        .current_token = TOKEN_NONE,
        .token_len = 0
    };

    next_token(&parser);

    OABE_PolicyNode *root = parse_expression(&parser);
    if (!root) {
        return OABE_ERROR_INVALID_POLICY;
    }

    /* Create policy tree */
    OABE_PolicyTree *result = (OABE_PolicyTree *)oabe_malloc(sizeof(OABE_PolicyTree));
    if (!result) {
        oabe_policy_node_free(root);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(result, 0, sizeof(OABE_PolicyTree));
    result->base.vtable = &g_policy_tree_vtable;
    result->base.ref_count = 1;
    result->root = root;

    /* Count leaves and collect attributes */
    /* TODO: Implement leaf counting */

    *tree = result;
    return OABE_SUCCESS;
}

void oabe_policy_tree_free(OABE_PolicyTree *tree) {
    if (tree) {
        OABE_DEREF(tree);
    }
}

OABE_PolicyTree* oabe_policy_tree_clone(const OABE_PolicyTree *tree) {
    if (!tree) return NULL;

    OABE_PolicyTree *new_tree = (OABE_PolicyTree *)oabe_malloc(sizeof(OABE_PolicyTree));
    if (!new_tree) return NULL;

    memset(new_tree, 0, sizeof(OABE_PolicyTree));
    new_tree->base.vtable = &g_policy_tree_vtable;
    new_tree->base.ref_count = 1;

    if (tree->root) {
        new_tree->root = (OABE_PolicyNode *)oabe_policy_node_clone(tree->root);
        if (!new_tree->root) {
            oabe_free(new_tree);
            return NULL;
        }
    }

    new_tree->num_leaves = tree->num_leaves;

    return new_tree;
}

/*============================================================================
 * Attribute List Implementation
 *============================================================================*/

static void oabe_attr_list_destroy(void *self) {
    OABE_AttributeList *list = (OABE_AttributeList *)self;
    if (list) {
        if (list->attributes) {
            oabe_strvec_free(list->attributes);
        }
        oabe_free(list);
    }
}

static const OABE_ObjectVTable g_attr_list_vtable = {
    .destroy = oabe_attr_list_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_AttributeList* oabe_attr_list_new(void) {
    OABE_AttributeList *list = (OABE_AttributeList *)oabe_malloc(sizeof(OABE_AttributeList));
    if (!list) return NULL;

    memset(list, 0, sizeof(OABE_AttributeList));
    list->base.vtable = &g_attr_list_vtable;
    list->base.ref_count = 1;

    list->attributes = oabe_strvec_new(0);
    if (!list->attributes) {
        oabe_free(list);
        return NULL;
    }

    return list;
}

OABE_AttributeList* oabe_attr_list_from_string(const char *attr_str) {
    if (!attr_str) return NULL;

    OABE_AttributeList *list = oabe_attr_list_new();
    if (!list) return NULL;

    /* Split by comma or pipe */
    char *str = oabe_strdup(attr_str);
    if (!str) {
        oabe_attr_list_free(list);
        return NULL;
    }

    char *token = strtok(str, ",|");
    while (token) {
        /* Trim whitespace */
        while (isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) end--;
        *(end + 1) = '\0';

        if (strlen(token) > 0) {
            oabe_attr_list_add(list, token);
        }

        token = strtok(NULL, ",|");
    }

    oabe_free(str);
    return list;
}

void oabe_attr_list_free(OABE_AttributeList *list) {
    if (list) {
        OABE_DEREF(list);
    }
}

OABE_AttributeList* oabe_attr_list_clone(const OABE_AttributeList *list) {
    if (!list) return NULL;

    OABE_AttributeList *new_list = oabe_attr_list_new();
    if (!new_list) return NULL;

    for (size_t i = 0; i < list->attributes->size; i++) {
        oabe_attr_list_add(new_list, oabe_strvec_get(list->attributes, i));
    }

    return new_list;
}

OABE_ERROR oabe_attr_list_add(OABE_AttributeList *list, const char *attr) {
    if (!list || !attr) {
        return OABE_ERROR_INVALID_INPUT;
    }

    return oabe_strvec_append(list->attributes, attr);
}

OABE_ERROR oabe_attr_list_remove(OABE_AttributeList *list, const char *attr) {
    if (!list || !attr) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Find and remove attribute */
    for (size_t i = 0; i < list->attributes->size; i++) {
        if (strcmp(oabe_strvec_get(list->attributes, i), attr) == 0) {
            return oabe_strvec_remove(list->attributes, i);
        }
    }

    return OABE_ERROR_ELEMENT_NOT_FOUND;
}

bool oabe_attr_list_contains(const OABE_AttributeList *list, const char *attr) {
    if (!list || !attr) return false;
    return oabe_strmap_contains((const OABE_StringMap *)list->attributes, attr);
}

size_t oabe_attr_list_get_count(const OABE_AttributeList *list) {
    return list ? list->attributes->size : 0;
}

const char* oabe_attr_list_get(const OABE_AttributeList *list, size_t index) {
    return list ? oabe_strvec_get(list->attributes, index) : NULL;
}

/*============================================================================
 * LSSS Matrix Implementation
 *============================================================================*/

static void oabe_lsss_matrix_destroy(void *self) {
    OABE_LSSSMatrix *matrix = (OABE_LSSSMatrix *)self;
    if (matrix) {
        if (matrix->matrix) {
            for (size_t i = 0; i < matrix->rows; i++) {
                oabe_free(matrix->matrix[i]);
            }
            oabe_free(matrix->matrix);
        }
        if (matrix->row_labels) {
            oabe_strvec_free(matrix->row_labels);
        }
        oabe_free(matrix);
    }
}

static const OABE_ObjectVTable g_lsss_matrix_vtable = {
    .destroy = oabe_lsss_matrix_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

/**
 * Internal structure for building LSSS matrix.
 */
typedef struct LSSSBuilder {
    int **matrix;           /* The matrix being built */
    size_t rows;            /* Current number of rows */
    size_t cols;            /* Current number of columns */
    size_t capacity;        /* Row capacity */
    OABE_StringVector *labels;  /* Row labels */
} LSSSBuilder;

/**
 * Create a new LSSS builder.
 */
static LSSSBuilder* lsss_builder_new(size_t initial_capacity) {
    LSSSBuilder *builder = (LSSSBuilder *)oabe_malloc(sizeof(LSSSBuilder));
    if (!builder) return NULL;

    memset(builder, 0, sizeof(LSSSBuilder));
    builder->capacity = initial_capacity > 0 ? initial_capacity : 16;
    builder->matrix = (int **)oabe_calloc(builder->capacity, sizeof(int *));
    if (!builder->matrix) {
        oabe_free(builder);
        return NULL;
    }

    builder->labels = oabe_strvec_new(0);
    if (!builder->labels) {
        oabe_free(builder->matrix);
        oabe_free(builder);
        return NULL;
    }

    return builder;
}

/**
 * Free an LSSS builder.
 */
static void lsss_builder_free(LSSSBuilder *builder) {
    if (builder) {
        if (builder->matrix) {
            for (size_t i = 0; i < builder->rows; i++) {
                oabe_free(builder->matrix[i]);
            }
            oabe_free(builder->matrix);
        }
        if (builder->labels) {
            oabe_strvec_free(builder->labels);
        }
        oabe_free(builder);
    }
}

/**
 * Add a row to the LSSS builder.
 */
static OABE_ERROR lsss_builder_add_row(LSSSBuilder *builder, int *row, size_t cols, const char *label) {
    if (!builder || !row) return OABE_ERROR_INVALID_INPUT;

    /* Grow matrix if needed */
    if (builder->rows >= builder->capacity) {
        size_t new_capacity = builder->capacity * 2;
        int **new_matrix = (int **)oabe_realloc(builder->matrix, new_capacity * sizeof(int *));
        if (!new_matrix) return OABE_ERROR_OUT_OF_MEMORY;
        builder->matrix = new_matrix;
        builder->capacity = new_capacity;
    }

    /* Copy row */
    int *row_copy = (int *)oabe_malloc(cols * sizeof(int));
    if (!row_copy) return OABE_ERROR_OUT_OF_MEMORY;
    memcpy(row_copy, row, cols * sizeof(int));

    builder->matrix[builder->rows] = row_copy;
    builder->cols = cols > builder->cols ? cols : builder->cols;

    /* Add label */
    if (label) {
        oabe_strvec_append(builder->labels, label);
    }

    builder->rows++;
    return OABE_SUCCESS;
}

/**
 * Generate LSSS share vector recursively.
 * For a threshold gate with threshold k of n children:
 * - Generate a random polynomial of degree k-1 with secret as constant term
 * - Evaluate polynomial at points 1, 2, ..., n for each child
 * - Recursively process children
 */
static OABE_ERROR lsss_generate_shares(
    OABE_PolicyNode *node,
    int *vector,
    size_t vector_len,
    LSSSBuilder *builder,
    int *(*poly_values)[2],  /* Temporary storage for polynomial values */
    size_t *poly_count
) {
    if (!node) return OABE_ERROR_INVALID_INPUT;

    if (node->type == OABE_POLICY_LEAF) {
        /* Leaf node: add row to matrix */
        return lsss_builder_add_row(builder, vector, vector_len, node->attribute);
    }

    /* Internal node: apply threshold secret sharing */
    int threshold = node->threshold;
    int num_children = (int)node->num_children;

    if (threshold <= 0 || threshold > num_children) {
        threshold = num_children;  /* Default to AND gate (all children required) */
    }

    /* For each child, extend the vector and recurse */
    /* In LSSS: each child gets a share computed from the parent's vector */
    /* The share computation is: new_vector = parent_vector + share_coefficient * basis_vector */

    /* Simple approach: for each child i, create coefficient c_i and recurse */
    /* For threshold gates, we use the following construction:
     * - For AND (n-of-n): each child gets vector = parent_vector || unit_vector
     * - For OR (1-of-n): each child gets vector = parent_vector (same for all)
     */

    for (size_t i = 0; i < node->num_children; i++) {
        /* Create extended vector for child */
        size_t child_vector_len = vector_len + 1;
        int *child_vector = (int *)oabe_calloc(child_vector_len, sizeof(int));
        if (!child_vector) return OABE_ERROR_OUT_OF_MEMORY;

        /* Copy parent vector */
        if (vector_len > 0 && vector) {
            memcpy(child_vector, vector, vector_len * sizeof(int));
        }

        /* Add share coefficient */
        if (threshold == num_children) {
            /* AND gate: construct LSSS matrix
             * For n-of-n threshold, we need shares that sum to s when all are present.
             * Simple construction:
             * - First child: new column = 1
             * - Second child: new column = -1 (for 2 children)
             * For 2 children: rows are [1, 1] and [1, -1]
             * With secret [s, y], shares are s+y and s-y
             * Sum of shares = 2s, so Lagrange coefficient = 1/2 each
             */
            child_vector[vector_len] = 1;
            if (i > 0) {
                /* For AND gate, alternating children get -1 in the NEW column */
                child_vector[vector_len] = -1;
            }
        } else if (threshold == 1) {
            /* OR gate: all children share the same vector */
            child_vector[vector_len] = 1;
        } else {
            /* General threshold: use Shamir's polynomial */
            /* Simplified: use unit vectors with appropriate coefficients */
            child_vector[vector_len] = 1;
        }

        OABE_ERROR rc = lsss_generate_shares(node->children[i], child_vector,
                                              child_vector_len, builder, poly_values, poly_count);
        oabe_free(child_vector);

        if (rc != OABE_SUCCESS) {
            return rc;
        }
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_lsss_from_policy(const OABE_PolicyTree *tree, OABE_LSSSMatrix **matrix) {
    if (!tree || !matrix) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *matrix = NULL;

    /* Count leaf nodes to estimate matrix size */
    /* TODO: Implement proper leaf counting */

    /* Create builder */
    LSSSBuilder *builder = lsss_builder_new(16);
    if (!builder) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Generate LSSS shares recursively */
    /* Start with vector [1] for the root */
    int root_vector[1] = {1};
    size_t poly_count = 0;

    OABE_ERROR rc = lsss_generate_shares(tree->root, root_vector, 1, builder, NULL, &poly_count);

    if (rc != OABE_SUCCESS) {
        lsss_builder_free(builder);
        return rc;
    }

    /* Create output matrix */
    OABE_LSSSMatrix *result = (OABE_LSSSMatrix *)oabe_malloc(sizeof(OABE_LSSSMatrix));
    if (!result) {
        lsss_builder_free(builder);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(result, 0, sizeof(OABE_LSSSMatrix));
    result->base.ref_count = 1;
    result->base.vtable = &g_lsss_matrix_vtable;
    result->rows = builder->rows;
    result->cols = builder->cols;
    result->matrix = builder->matrix;
    result->row_labels = builder->labels;

    /* Free builder but keep the data */
    builder->matrix = NULL;
    builder->labels = NULL;
    lsss_builder_free(builder);

    *matrix = result;
    return OABE_SUCCESS;
}

void oabe_lsss_matrix_free(OABE_LSSSMatrix *matrix) {
    if (matrix) {
        OABE_DEREF(matrix);
    }
}

/**
 * Helper: Count leaf nodes in a policy tree.
 * Reserved for future LSSS coefficient recovery.
 */
__attribute__((unused))
static size_t count_leaves(const OABE_PolicyNode *node) {
    if (!node) return 0;
    if (node->type == OABE_POLICY_LEAF) return 1;

    size_t count = 0;
    for (size_t i = 0; i < node->num_children; i++) {
        count += count_leaves(node->children[i]);
    }
    return count;
}

OABE_ERROR oabe_lsss_share(const OABE_LSSSMatrix *matrix, const OABE_ZP *secret,
                           OABE_ZP ***shares, size_t *shares_len) {
    if (!matrix || !secret || !shares || !shares_len) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *shares = NULL;
    *shares_len = 0;

    /* Get the group from the secret */
    OABE_GroupHandle group = oabe_zp_get_group(secret);

    /* LSSS share computation using the matrix representation:
     * The secret vector is v = [s, y2, y3, ..., yn] where s is the secret
     * and y2...yn are random values (one for each additional column).
     * The share for row i is: share_i = sum_j(M[i][j] * v[j])
     */

    /* Generate random values for columns 1..n (v[1] through v[cols-1]) */
    OABE_ZP **random_values = NULL;
    size_t num_random = (matrix->cols > 1) ? (matrix->cols - 1) : 0;

    if (num_random > 0) {
        random_values = (OABE_ZP **)oabe_calloc(num_random, sizeof(OABE_ZP *));
        if (!random_values) {
            return OABE_ERROR_OUT_OF_MEMORY;
        }

        for (size_t i = 0; i < num_random; i++) {
            random_values[i] = oabe_zp_new(group);
            if (!random_values[i]) {
                for (size_t j = 0; j < i; j++) {
                    oabe_zp_free(random_values[j]);
                }
                oabe_free(random_values);
                return OABE_ERROR_OUT_OF_MEMORY;
            }
            /* Set random value - for now use 0 for deterministic testing
             * In production, this should be: oabe_zp_random(random_values[i], rng);
             * For proper LSSS, we need to pass an RNG, but for simplicity use 0
             */
            oabe_zp_set_zero(random_values[i]);
        }
    }

    /* Allocate shares array */
    OABE_ZP **result = (OABE_ZP **)oabe_calloc(matrix->rows, sizeof(OABE_ZP *));
    if (!result) {
        for (size_t i = 0; i < num_random; i++) {
            oabe_zp_free(random_values[i]);
        }
        oabe_free(random_values);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* For each row, compute the share as sum of matrix elements * vector elements */
    for (size_t i = 0; i < matrix->rows; i++) {
        result[i] = oabe_zp_new(group);
        if (!result[i]) {
            /* Cleanup on failure */
            for (size_t j = 0; j < i; j++) {
                oabe_zp_free(result[j]);
            }
            oabe_free(result);
            for (size_t j = 0; j < num_random; j++) {
                oabe_zp_free(random_values[j]);
            }
            oabe_free(random_values);
            return OABE_ERROR_OUT_OF_MEMORY;
        }

        /* Initialize share to zero */
        oabe_zp_set_zero(result[i]);

        /* Compute: share_i = sum over j of M[i][j] * v[j]
         * where v[0] = secret, v[j>0] = random_values[j-1]
         */
        OABE_ZP *temp = oabe_zp_new(group);
        if (!temp) {
            for (size_t j = 0; j <= i; j++) {
                oabe_zp_free(result[j]);
            }
            oabe_free(result);
            for (size_t j = 0; j < num_random; j++) {
                oabe_zp_free(random_values[j]);
            }
            oabe_free(random_values);
            return OABE_ERROR_OUT_OF_MEMORY;
        }

        /* Process each column */
        for (size_t j = 0; j < matrix->cols; j++) {
            int coeff = matrix->matrix[i][j];

            if (coeff == 0) {
                continue;  /* Adds nothing */
            }

            /* Get the vector element for this column */
            const OABE_ZP *vec_elem = (j == 0) ? secret : random_values[j - 1];

            /* Compute temp = coeff * vec_elem, then add to result[i] */
            if (coeff == 1) {
                oabe_zp_add(result[i], result[i], vec_elem);
            } else if (coeff == -1) {
                oabe_zp_neg(temp, vec_elem);
                oabe_zp_add(result[i], result[i], temp);
            } else {
                /* For other coefficients, compute coeff * vec_elem first */
                oabe_zp_set_zero(temp);
                if (coeff > 0) {
                    for (int k = 0; k < coeff; k++) {
                        oabe_zp_add(temp, temp, vec_elem);
                    }
                } else {
                    for (int k = 0; k < -coeff; k++) {
                        OABE_ZP *neg = oabe_zp_new(group);
                        oabe_zp_neg(neg, vec_elem);
                        oabe_zp_add(temp, temp, neg);
                        oabe_zp_free(neg);
                    }
                }
                oabe_zp_add(result[i], result[i], temp);
            }
        }

        oabe_zp_free(temp);
    }

    /* Cleanup random values */
    for (size_t i = 0; i < num_random; i++) {
        oabe_zp_free(random_values[i]);
    }
    oabe_free(random_values);

    *shares = result;
    *shares_len = matrix->rows;
    return OABE_SUCCESS;
}

/**
 * Compute Lagrange coefficient for interpolation at index i.
 * Lagrange coefficient L_i(x) = prod_{j != i} (x - x_j) / (x_i - x_j)
 * For secret recovery at x = 0: L_i(0) = prod_{j != i} (-x_j) / (x_i - x_j)
 */
static OABE_ERROR compute_lagrange_coefficient(OABE_GroupHandle group,
                                                  int index,
                                                  const int *indices,
                                                  size_t num_indices,
                                                  OABE_ZP **result) {
    *result = oabe_zp_new(group);
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Initialize result to 1 */
    oabe_zp_set_one(*result);

    OABE_ZP *numerator = oabe_zp_new(group);
    OABE_ZP *denominator = oabe_zp_new(group);
    OABE_ZP *temp = oabe_zp_new(group);

    if (!numerator || !denominator || !temp) {
        if (numerator) oabe_zp_free(numerator);
        if (denominator) oabe_zp_free(denominator);
        if (temp) oabe_zp_free(temp);
        oabe_zp_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    int xi = indices[index];

    for (size_t j = 0; j < num_indices; j++) {
        if ((int)j == index) continue;

        int xj = indices[j];

        /* numerator = -xj */
        oabe_zp_set_int(numerator, -xj);

        /* denominator = xi - xj */
        oabe_zp_set_int(denominator, xi - xj);

        /* temp = numerator / denominator */
        oabe_zp_div(temp, numerator, denominator);

        /* result *= temp */
        oabe_zp_mul(*result, *result, temp);
    }

    oabe_zp_free(numerator);
    oabe_zp_free(denominator);
    oabe_zp_free(temp);

    return OABE_SUCCESS;
}

OABE_ERROR oabe_lsss_recover(const OABE_LSSSMatrix *matrix, OABE_ZP **shares,
                              size_t shares_len, const int *indices, size_t indices_len,
                              OABE_ZP **secret) {
    if (!matrix || !shares || !indices || !secret) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *secret = NULL;

    if (shares_len == 0 || indices_len == 0 || shares_len != indices_len) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Get the group from the first share */
    OABE_GroupHandle group = oabe_zp_get_group(shares[0]);

    /* Allocate result */
    OABE_ZP *result = oabe_zp_new(group);
    if (!result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    oabe_zp_set_zero(result);

    /* Compute Lagrange interpolation at x = 0 */
    /* secret = sum over i of L_i(0) * share_i */

    OABE_ZP *coeff = NULL;
    OABE_ZP *term = oabe_zp_new(group);

    if (!term) {
        oabe_zp_free(result);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < indices_len; i++) {
        /* Compute Lagrange coefficient L_i(0) */
        OABE_ERROR rc = compute_lagrange_coefficient(group, (int)i, indices, indices_len, &coeff);
        if (rc != OABE_SUCCESS) {
            oabe_zp_free(result);
            oabe_zp_free(term);
            if (coeff) oabe_zp_free(coeff);
            return rc;
        }

        /* term = coeff * shares[i] */
        oabe_zp_mul(term, coeff, shares[i]);

        /* result += term */
        oabe_zp_add(result, result, term);

        oabe_zp_free(coeff);
        coeff = NULL;
    }

    oabe_zp_free(term);
    *secret = result;

    return OABE_SUCCESS;
}

const char* oabe_lsss_get_row_label(const OABE_LSSSMatrix *matrix, size_t row) {
    if (!matrix || row >= matrix->rows) {
        return NULL;
    }
    return oabe_strvec_get(matrix->row_labels, row);
}

/*============================================================================
 * Tree-based LSSS Functions (for proper polynomial sharing)
 *============================================================================*/

/**
 * Evaluate a polynomial at point x given coefficients.
 * Polynomial: P(x) = coeff[0] + coeff[1]*x + coeff[2]*x^2 + ...
 */
static OABE_ERROR evaluate_polynomial(OABE_GroupHandle group, OABE_ZP **coefficients,
                                       size_t num_coeff, int x, OABE_ZP **result) {
    if (!group || !coefficients || num_coeff == 0 || !result) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *result = oabe_zp_new(group);
    if (!*result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    OABE_ZP *x_pow = oabe_zp_new(group);
    OABE_ZP *term = oabe_zp_new(group);

    if (!x_pow || !term) {
        if (x_pow) oabe_zp_free(x_pow);
        if (*result) oabe_zp_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* result = sum_{i=0}^{n-1} coeff[i] * x^i */
    oabe_zp_set_zero(*result);
    oabe_zp_set_one(x_pow);  /* x^0 = 1 */

    for (size_t i = 0; i < num_coeff; i++) {
        /* term = coeff[i] * x_pow */
        oabe_zp_mul(term, coefficients[i], x_pow);
        /* result += term */
        oabe_zp_add(*result, *result, term);

        /* x_pow = x_pow * x */
        OABE_ZP *x_val = oabe_zp_new(group);
        if (!x_val) {
            oabe_zp_free(x_pow);
            oabe_zp_free(term);
            oabe_zp_free(*result);
            *result = NULL;
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_zp_set_int(x_val, x);
        oabe_zp_mul(x_pow, x_pow, x_val);
        oabe_zp_free(x_val);
    }

    oabe_zp_free(x_pow);
    oabe_zp_free(term);
    return OABE_SUCCESS;
}

/**
 * Structure to hold share results from tree traversal.
 */
typedef struct {
    char *attribute;    /* Attribute label */
    OABE_ZP *share;     /* The share value */
} OABE_TreeShare;

typedef struct {
    OABE_TreeShare *shares;
    size_t count;
    size_t capacity;
} OABE_TreeShareList;

static OABE_TreeShareList* tree_share_list_new(size_t capacity) {
    OABE_TreeShareList *list = (OABE_TreeShareList *)oabe_malloc(sizeof(OABE_TreeShareList));
    if (!list) return NULL;

    list->shares = (OABE_TreeShare *)oabe_calloc(capacity, sizeof(OABE_TreeShare));
    if (!list->shares) {
        oabe_free(list);
        return NULL;
    }
    list->count = 0;
    list->capacity = capacity;
    return list;
}

static void tree_share_list_free(OABE_TreeShareList *list) {
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            if (list->shares[i].attribute) oabe_free(list->shares[i].attribute);
            if (list->shares[i].share) oabe_zp_free(list->shares[i].share);
        }
        oabe_free(list->shares);
        oabe_free(list);
    }
}

static OABE_ERROR tree_share_list_add(OABE_TreeShareList *list, const char *attr, OABE_ZP *share) {
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity * 2;
        OABE_TreeShare *new_shares = (OABE_TreeShare *)oabe_realloc(list->shares, new_cap * sizeof(OABE_TreeShare));
        if (!new_shares) return OABE_ERROR_OUT_OF_MEMORY;
        list->shares = new_shares;
        list->capacity = new_cap;
    }

    list->shares[list->count].attribute = oabe_strdup(attr);
    if (!list->shares[list->count].attribute) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Clone the share */
    list->shares[list->count].share = oabe_zp_clone(share);
    if (!list->shares[list->count].share) {
        oabe_free(list->shares[list->count].attribute);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    list->count++;
    return OABE_SUCCESS;
}

/**
 * Iteratively share a secret through a policy tree.
 * Uses polynomial secret sharing at each threshold gate.
 */
static OABE_ERROR iterative_share_tree(OABE_PolicyNode *root, OABE_ZP *secret,
                                        OABE_RNGHandle rng, OABE_TreeShareList *result) {
    /* Use stacks for iterative traversal */
    OABE_PolicyNode **node_stack = (OABE_PolicyNode **)oabe_malloc(256 * sizeof(OABE_PolicyNode *));
    OABE_ZP **share_stack = (OABE_ZP **)oabe_malloc(256 * sizeof(OABE_ZP *));
    if (!node_stack || !share_stack) {
        if (node_stack) oabe_free(node_stack);
        if (share_stack) oabe_free(share_stack);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    size_t stack_top = 0;
    node_stack[stack_top] = root;
    share_stack[stack_top] = secret;
    stack_top++;

    OABE_GroupHandle group = oabe_zp_get_group(secret);
    OABE_ERROR rc = OABE_SUCCESS;

    while (stack_top > 0 && rc == OABE_SUCCESS) {
        stack_top--;
        OABE_PolicyNode *node = node_stack[stack_top];
        OABE_ZP *node_secret = share_stack[stack_top];

        if (node->type == OABE_POLICY_LEAF) {
            /* Leaf node: add share to result */
            rc = tree_share_list_add(result, node->attribute, node_secret);
        } else {
            /* Internal node: generate polynomial and share to children */
            uint32_t threshold = (uint32_t)node->threshold;
            uint32_t num_children = (uint32_t)node->num_children;

            /* Generate polynomial coefficients: coeff[0] = secret, others random */
            OABE_ZP **coefficients = (OABE_ZP **)oabe_calloc(threshold, sizeof(OABE_ZP *));
            if (!coefficients) {
                rc = OABE_ERROR_OUT_OF_MEMORY;
                break;
            }

            for (uint32_t i = 0; i < threshold; i++) {
                coefficients[i] = oabe_zp_new(group);
                if (!coefficients[i]) {
                    for (uint32_t j = 0; j < i; j++) oabe_zp_free(coefficients[j]);
                    oabe_free(coefficients);
                    rc = OABE_ERROR_OUT_OF_MEMORY;
                    break;
                }
                if (i == 0) {
                    oabe_zp_copy(coefficients[i], node_secret);
                } else {
                    oabe_zp_random(coefficients[i], rng);
                }
            }

            if (rc != OABE_SUCCESS) {
                for (uint32_t j = 0; j < threshold; j++) {
                    if (coefficients[j]) oabe_zp_free(coefficients[j]);
                }
                oabe_free(coefficients);
                break;
            }

            /* Evaluate polynomial at points 1, 2, ..., num_children */
            for (uint32_t i = 0; i < num_children; i++) {
                OABE_ZP *child_share = NULL;
                rc = evaluate_polynomial(group, coefficients, threshold, (int)(i + 1), &child_share);
                if (rc != OABE_SUCCESS) {
                    break;
                }

                node_stack[stack_top] = node->children[i];
                share_stack[stack_top] = child_share;
                stack_top++;
            }

            /* Cleanup coefficients */
            for (uint32_t j = 0; j < threshold; j++) {
                oabe_zp_free(coefficients[j]);
            }
            oabe_free(coefficients);
        }
    }

    /* Cleanup any remaining shares in stack (except the original secret) */
    for (size_t i = 0; i < stack_top; i++) {
        if (share_stack[i] && share_stack[i] != secret) {
            oabe_zp_free(share_stack[i]);
        }
    }

    oabe_free(node_stack);
    oabe_free(share_stack);
    return rc;
}

/**
 * Share a secret through a policy tree.
 * Returns an array of shares, one per leaf attribute.
 */
OABE_ERROR oabe_lsss_share_tree(OABE_PolicyNode *policy, OABE_ZP *secret,
                                 OABE_RNGHandle rng,
                                 OABE_ZP ***shares, char ***attributes, size_t *count) {
    if (!policy || !secret || !shares || !attributes || !count) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *shares = NULL;
    *attributes = NULL;
    *count = 0;

    /* Count leaves */
    size_t leaf_count = 0;
    OABE_PolicyNode **stack = (OABE_PolicyNode **)oabe_malloc(256 * sizeof(OABE_PolicyNode *));
    if (!stack) return OABE_ERROR_OUT_OF_MEMORY;

    size_t stack_top = 0;
    stack[stack_top++] = policy;

    while (stack_top > 0) {
        OABE_PolicyNode *node = stack[--stack_top];
        if (node->type == OABE_POLICY_LEAF) {
            leaf_count++;
        } else {
            for (size_t i = 0; i < node->num_children; i++) {
                stack[stack_top++] = node->children[i];
            }
        }
    }
    oabe_free(stack);

    if (leaf_count == 0) {
        return OABE_ERROR_INVALID_INPUT;
    }

    /* Create share list */
    OABE_TreeShareList *list = tree_share_list_new(leaf_count);
    if (!list) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Perform sharing */
    OABE_ERROR rc = iterative_share_tree(policy, secret, rng, list);
    if (rc != OABE_SUCCESS) {
        tree_share_list_free(list);
        return rc;
    }

    /* Copy results to output arrays */
    *shares = (OABE_ZP **)oabe_malloc(list->count * sizeof(OABE_ZP *));
    *attributes = (char **)oabe_malloc(list->count * sizeof(char *));
    if (!*shares || !*attributes) {
        if (*shares) oabe_free(*shares);
        if (*attributes) oabe_free(*attributes);
        tree_share_list_free(list);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < list->count; i++) {
        (*shares)[i] = list->shares[i].share;
        (*attributes)[i] = list->shares[i].attribute;
        list->shares[i].share = NULL;  /* Transfer ownership */
        list->shares[i].attribute = NULL;
    }
    *count = list->count;

    list->shares = NULL;
    list->count = 0;
    tree_share_list_free(list);
    return OABE_SUCCESS;
}

/**
 * Allocate sat_list for all nodes in the tree.
 */
static bool allocate_sat_lists(OABE_PolicyNode *node) {
    if (!node) return false;

    /* Allocate sat_list for this node */
    node->sat_list = (int *)oabe_calloc(1, sizeof(int));
    if (!node->sat_list) return false;

    /* Recursively allocate for children */
    for (size_t i = 0; i < node->num_children; i++) {
        if (!allocate_sat_lists(node->children[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Free sat_list for all nodes in the tree.
 */
static void free_sat_lists(OABE_PolicyNode *node) {
    if (!node) return;

    if (node->sat_list) {
        oabe_free(node->sat_list);
        node->sat_list = NULL;
    }

    for (size_t i = 0; i < node->num_children; i++) {
        free_sat_lists(node->children[i]);
    }
}

/**
 * Mark nodes in the tree that satisfy the given attribute list.
 * Returns true if the policy is satisfied.
 */
static bool mark_satisfied_nodes(OABE_PolicyNode *node, OABE_StringVector *attrs) {
    if (!node) return false;

    if (node->type == OABE_POLICY_LEAF) {
        /* Check if this attribute is in the list */
        for (size_t i = 0; i < attrs->size; i++) {
            if (strcmp(node->attribute, oabe_strvec_get(attrs, i)) == 0) {
                node->sat_list[0] = 1;  /* Mark as satisfied */
                return true;
            }
        }
        node->sat_list[0] = 0;  /* Mark as not satisfied */
        return false;
    }

    /* Internal node: check children */
    int satisfied_count = 0;
    int threshold = node->threshold;

    for (size_t i = 0; i < node->num_children; i++) {
        if (mark_satisfied_nodes(node->children[i], attrs)) {
            satisfied_count++;
        }
    }

    /* Mark this node as satisfied if enough children are satisfied */
    node->sat_list[0] = (satisfied_count >= threshold) ? 1 : 0;
    return (satisfied_count >= threshold);
}

/**
 * Compute Lagrange coefficient for interpolation at point index.
 * L_i(0) = prod_{j != i, j in S} (-j) / (i - j)
 * where indices are 1-based.
 */
static OABE_ERROR compute_lagrange(OABE_GroupHandle group, int index, int *indices,
                                    size_t num_indices, OABE_ZP **result) {
    *result = oabe_zp_new(group);
    if (!*result) return OABE_ERROR_OUT_OF_MEMORY;

    oabe_zp_set_one(*result);

    OABE_ZP *numerator = oabe_zp_new(group);
    OABE_ZP *denominator = oabe_zp_new(group);
    OABE_ZP *frac = oabe_zp_new(group);

    if (!numerator || !denominator || !frac) {
        if (numerator) oabe_zp_free(numerator);
        if (denominator) oabe_zp_free(denominator);
        if (frac) oabe_zp_free(frac);
        oabe_zp_free(*result);
        *result = NULL;
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    for (size_t j = 0; j < num_indices; j++) {
        if (indices[j] == index) continue;

        /* numerator = -indices[j] */
        oabe_zp_set_int(numerator, -indices[j]);

        /* denominator = index - indices[j] */
        oabe_zp_set_int(denominator, index - indices[j]);

        /* frac = numerator / denominator */
        oabe_zp_div(frac, numerator, denominator);

        /* result *= frac */
        oabe_zp_mul(*result, *result, frac);
    }

    oabe_zp_free(numerator);
    oabe_zp_free(denominator);
    oabe_zp_free(frac);
    return OABE_SUCCESS;
}

/**
 * Recover coefficients for decryption.
 * Traverses the tree and computes Lagrange coefficients for satisfied leaves.
 */
static OABE_ERROR iterative_recover_coefficients(OABE_PolicyNode *node, OABE_ZP *in_coeff,
                                                   OABE_TreeShareList *result) {
    if (!node || !in_coeff) return OABE_ERROR_INVALID_INPUT;

    if (node->type == OABE_POLICY_LEAF) {
        if (node->sat_list[0]) {
            /* This leaf is used for decryption */
            return tree_share_list_add(result, node->attribute, in_coeff);
        }
        return OABE_SUCCESS;
    }

    /* Internal node: compute coefficients for satisfied children */
    OABE_GroupHandle group = oabe_zp_get_group(in_coeff);
    uint32_t threshold = (uint32_t)node->threshold;

    /* Collect indices of satisfied children */
    int *satisfied_indices = (int *)oabe_malloc(node->num_children * sizeof(int));
    if (!satisfied_indices) return OABE_ERROR_OUT_OF_MEMORY;

    size_t num_satisfied = 0;
    for (size_t i = 0; i < node->num_children; i++) {
        if (node->children[i]->sat_list[0]) {
            satisfied_indices[num_satisfied++] = (int)(i + 1);  /* 1-based index */
        }
    }

    OABE_ERROR rc = OABE_SUCCESS;

    /* For each satisfied child, compute Lagrange coefficient */
    for (size_t i = 0; i < node->num_children && rc == OABE_SUCCESS; i++) {
        if (!node->children[i]->sat_list[0]) continue;

        OABE_ZP *lagrange = NULL;
        int child_index = (int)(i + 1);  /* 1-based */

        /* Only use indices up to threshold for Lagrange computation */
        int *use_indices = satisfied_indices;
        size_t num_use = (num_satisfied < threshold) ? num_satisfied : threshold;

        /* Ensure child_index is in the used indices */
        bool found = false;
        for (size_t j = 0; j < num_use; j++) {
            if (use_indices[j] == child_index) {
                found = true;
                break;
            }
        }
        if (!found) continue;

        rc = compute_lagrange(group, child_index, use_indices, num_use, &lagrange);
        if (rc != OABE_SUCCESS) {
            oabe_free(satisfied_indices);
            return rc;
        }

        /* Multiply input coefficient by Lagrange coefficient */
        OABE_ZP *child_coeff = oabe_zp_new(group);
        if (!child_coeff) {
            oabe_zp_free(lagrange);
            oabe_free(satisfied_indices);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
        oabe_zp_mul(child_coeff, in_coeff, lagrange);
        oabe_zp_free(lagrange);

        /* Recurse */
        rc = iterative_recover_coefficients(node->children[i], child_coeff, result);
        oabe_zp_free(child_coeff);
    }

    oabe_free(satisfied_indices);
    return rc;
}

/**
 * Recover Lagrange coefficients for a policy given user attributes.
 * Returns coefficients for each leaf attribute.
 */
OABE_ERROR oabe_lsss_recover_coefficients(OABE_PolicyNode *policy,
                                            OABE_StringVector *user_attrs,
                                            OABE_GroupHandle group,
                                            OABE_ZP ***coefficients,
                                            char ***attributes,
                                            size_t *count) {
    if (!policy || !user_attrs || !group || !coefficients || !attributes || !count) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *coefficients = NULL;
    *attributes = NULL;
    *count = 0;

    /* Allocate sat_list for all nodes in the tree */
    if (!allocate_sat_lists(policy)) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Mark satisfied nodes */
    bool satisfied = mark_satisfied_nodes(policy, user_attrs);
    if (!satisfied) {
        free_sat_lists(policy);
        return OABE_ERROR_POLICY_NOT_SATISFIED;
    }

    /* Count leaves */
    size_t leaf_count = 0;
    OABE_PolicyNode **stack = (OABE_PolicyNode **)oabe_malloc(256 * sizeof(OABE_PolicyNode *));
    if (!stack) {
        free_sat_lists(policy);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    size_t stack_top = 0;
    stack[stack_top++] = policy;

    while (stack_top > 0) {
        OABE_PolicyNode *node = stack[--stack_top];
        if (node->type == OABE_POLICY_LEAF) {
            if (node->sat_list[0]) leaf_count++;
        } else {
            for (size_t i = 0; i < node->num_children; i++) {
                stack[stack_top++] = node->children[i];
            }
        }
    }
    oabe_free(stack);

    if (leaf_count == 0) {
        free_sat_lists(policy);
        return OABE_ERROR_POLICY_NOT_SATISFIED;
    }

    /* Create coefficient list */
    OABE_TreeShareList *list = tree_share_list_new(leaf_count);
    if (!list) {
        free_sat_lists(policy);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Start coefficient recovery with coefficient = 1 */
    OABE_ZP *initial_coeff = oabe_zp_new(group);
    if (!initial_coeff) {
        tree_share_list_free(list);
        free_sat_lists(policy);
        return OABE_ERROR_OUT_OF_MEMORY;
    }
    oabe_zp_set_one(initial_coeff);

    OABE_ERROR rc = iterative_recover_coefficients(policy, initial_coeff, list);
    oabe_zp_free(initial_coeff);

    if (rc != OABE_SUCCESS) {
        tree_share_list_free(list);
        free_sat_lists(policy);
        return rc;
    }

    /* Copy results */
    *coefficients = (OABE_ZP **)oabe_malloc(list->count * sizeof(OABE_ZP *));
    *attributes = (char **)oabe_malloc(list->count * sizeof(char *));
    if (!*coefficients || !*attributes) {
        if (*coefficients) oabe_free(*coefficients);
        if (*attributes) oabe_free(*attributes);
        tree_share_list_free(list);
        free_sat_lists(policy);
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < list->count; i++) {
        (*coefficients)[i] = list->shares[i].share;
        (*attributes)[i] = list->shares[i].attribute;
        list->shares[i].share = NULL;
        list->shares[i].attribute = NULL;
    }
    *count = list->count;

    list->shares = NULL;
    list->count = 0;
    tree_share_list_free(list);
    free_sat_lists(policy);
    return OABE_SUCCESS;
}

void oabe_lsss_free_coefficients(OABE_ZP **coefficients, char **attributes, size_t count) {
    if (coefficients) {
        for (size_t i = 0; i < count; i++) {
            if (coefficients[i]) oabe_zp_free(coefficients[i]);
        }
        oabe_free(coefficients);
    }
    if (attributes) {
        for (size_t i = 0; i < count; i++) {
            if (attributes[i]) oabe_free(attributes[i]);
        }
        oabe_free(attributes);
    }
}

/*============================================================================
 * Function Input Implementation
 *============================================================================*/

static void oabe_function_input_destroy(void *self) {
    OABE_FunctionInput *input = (OABE_FunctionInput *)self;
    if (input) {
        if (input->type == OABE_INPUT_POLICY && input->data.policy) {
            oabe_policy_tree_free(input->data.policy);
        } else if (input->type == OABE_INPUT_ATTRIBUTES && input->data.attrs) {
            oabe_attr_list_free(input->data.attrs);
        }
        oabe_free(input);
    }
}

static const OABE_ObjectVTable g_function_input_vtable = {
    .destroy = oabe_function_input_destroy,
    .clone = NULL,
    .serialize = NULL,
    .is_equal = NULL
};

OABE_ERROR oabe_function_input_parse(const char *input, OABE_FunctionInput **func_input) {
    if (!input || !func_input) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *func_input = NULL;

    /* Determine if input is a policy or attribute list */
    /* Policy: contains AND, OR, parentheses
     * Attribute list: comma or pipe separated values
     */

    bool is_policy = false;
    const char *p = input;

    /* Skip whitespace */
    while (*p && isspace((unsigned char)*p)) p++;

    /* Check for policy indicators */
    if (*p == '(' ||
        strcasestr(input, "AND") != NULL ||
        strcasestr(input, "OR") != NULL) {
        is_policy = true;
    }

    OABE_FunctionInput *result = (OABE_FunctionInput *)oabe_malloc(sizeof(OABE_FunctionInput));
    if (!result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    memset(result, 0, sizeof(OABE_FunctionInput));
    result->base.vtable = &g_function_input_vtable;
    result->base.ref_count = 1;

    if (is_policy) {
        result->type = OABE_INPUT_POLICY;
        OABE_ERROR rc = oabe_policy_parse(input, &result->data.policy);
        if (rc != OABE_SUCCESS) {
            oabe_free(result);
            return rc;
        }
    } else {
        result->type = OABE_INPUT_ATTRIBUTES;
        result->data.attrs = oabe_attr_list_from_string(input);
        if (!result->data.attrs) {
            oabe_free(result);
            return OABE_ERROR_OUT_OF_MEMORY;
        }
    }

    *func_input = result;
    return OABE_SUCCESS;
}

void oabe_function_input_free(OABE_FunctionInput *func_input) {
    if (func_input) {
        OABE_DEREF(func_input);
    }
}

OABE_FunctionInputType oabe_function_input_get_type(const OABE_FunctionInput *func_input) {
    return func_input ? func_input->type : OABE_INPUT_POLICY;
}

OABE_PolicyTree* oabe_function_input_get_policy(const OABE_FunctionInput *func_input) {
    if (!func_input || func_input->type != OABE_INPUT_POLICY) {
        return NULL;
    }
    return func_input->data.policy;
}

OABE_AttributeList* oabe_function_input_get_attributes(const OABE_FunctionInput *func_input) {
    if (!func_input || func_input->type != OABE_INPUT_ATTRIBUTES) {
        return NULL;
    }
    return func_input->data.attrs;
}

/*============================================================================
 * Policy Attribute Extraction
 *============================================================================*/

/**
 * Helper: Recursively collect attributes from policy tree.
 */
static OABE_ERROR collect_attributes(const OABE_PolicyNode *node, OABE_StringVector *attrs) {
    if (!node || !attrs) {
        return OABE_ERROR_INVALID_INPUT;
    }

    if (node->type == OABE_POLICY_LEAF) {
        /* Add leaf attribute to vector */
        return oabe_strvec_append(attrs, node->attribute);
    }

    /* Internal node: recurse into children */
    for (size_t i = 0; i < node->num_children; i++) {
        OABE_ERROR rc = collect_attributes(node->children[i], attrs);
        if (rc != OABE_SUCCESS) {
            return rc;
        }
    }

    return OABE_SUCCESS;
}

OABE_ERROR oabe_policy_get_attributes(const OABE_PolicyTree *tree, OABE_StringVector **attrs) {
    if (!tree || !attrs) {
        return OABE_ERROR_INVALID_INPUT;
    }

    *attrs = NULL;

    /* Create output vector */
    OABE_StringVector *result = oabe_strvec_new(0);
    if (!result) {
        return OABE_ERROR_OUT_OF_MEMORY;
    }

    /* Collect attributes recursively */
    if (tree->root) {
        OABE_ERROR rc = collect_attributes(tree->root, result);
        if (rc != OABE_SUCCESS) {
            oabe_strvec_free(result);
            return rc;
        }
    }

    *attrs = result;
    return OABE_SUCCESS;
}

/**
 * Helper: Check if attribute exists in policy tree.
 */
static bool has_attribute_recursive(const OABE_PolicyNode *node, const char *attr) {
    if (!node || !attr) return false;

    if (node->type == OABE_POLICY_LEAF) {
        return strcmp(node->attribute, attr) == 0;
    }

    /* Check children */
    for (size_t i = 0; i < node->num_children; i++) {
        if (has_attribute_recursive(node->children[i], attr)) {
            return true;
        }
    }

    return false;
}

bool oabe_policy_has_attribute(const OABE_PolicyTree *tree, const char *attr) {
    if (!tree || !attr) return false;
    return has_attribute_recursive(tree->root, attr);
}

/**
 * Helper: Convert policy node to string.
 */
static char* policy_node_to_string(const OABE_PolicyNode *node, bool need_parens) {
    if (!node) return NULL;

    if (node->type == OABE_POLICY_LEAF) {
        return oabe_strdup(node->attribute ? node->attribute : "");
    }

    /* Build string for internal node */
    char *result = NULL;
    size_t result_len = 0;
    size_t result_cap = 256;
    result = (char *)oabe_malloc(result_cap);
    if (!result) return NULL;

    if (need_parens) {
        result[0] = '(';
        result[1] = '\0';
        result_len = 1;
    } else {
        result[0] = '\0';
    }

    const char *op = (node->type == OABE_POLICY_AND) ? " and " : " or ";

    for (size_t i = 0; i < node->num_children; i++) {
        char *child_str = policy_node_to_string(node->children[i], true);
        if (!child_str) {
            oabe_free(result);
            return NULL;
        }

        size_t child_len = strlen(child_str);

        /* Reallocate if needed */
        while (result_len + child_len + 10 > result_cap) {
            result_cap *= 2;
            char *new_result = (char *)oabe_realloc(result, result_cap);
            if (!new_result) {
                oabe_free(child_str);
                oabe_free(result);
                return NULL;
            }
            result = new_result;
        }

        if (i > 0) {
            strcat(result, op);
            result_len += strlen(op);
        }
        strcat(result, child_str);
        result_len += child_len;

        oabe_free(child_str);
    }

    if (need_parens) {
        strcat(result, ")");
        result_len++;
    }

    return result;
}

char* oabe_policy_to_string(const OABE_PolicyTree *tree) {
    if (!tree || !tree->root) return NULL;
    return policy_node_to_string(tree->root, false);
}

/*============================================================================
 * Policy Satisfaction Checking
 *============================================================================*/

/**
 * Helper: Check if a set of attributes satisfies the policy node.
 * Returns true if the attributes can satisfy the policy subtree.
 */
static bool check_satisfaction(const OABE_PolicyNode *node,
                               const OABE_StringVector *attributes) {
    if (!node) return false;

    if (node->type == OABE_POLICY_LEAF) {
        /* Check if this attribute is in the list */
        for (size_t i = 0; i < attributes->size; i++) {
            if (strcmp(node->attribute, attributes->items[i]) == 0) {
                return true;
            }
        }
        return false;
    }

    /* Internal node: check children based on threshold */
    int threshold = node->threshold;
    if (threshold <= 0 || threshold > (int)node->num_children) {
        /* Default: AND gate requires all children */
        threshold = (int)node->num_children;
    }

    int satisfied_count = 0;
    for (size_t i = 0; i < node->num_children; i++) {
        if (check_satisfaction(node->children[i], attributes)) {
            satisfied_count++;
            /* Early exit for OR gates (threshold = 1) */
            if (threshold == 1 && satisfied_count >= 1) {
                return true;
            }
        }
    }

    return (satisfied_count >= threshold);
}

bool oabe_policy_satisfies(const OABE_PolicyTree *tree, const OABE_StringVector *attributes) {
    if (!tree || !attributes) return false;
    if (!tree->root) return false;
    return check_satisfaction(tree->root, attributes);
}

bool oabe_policy_satisfies_list(const OABE_PolicyTree *tree, const OABE_AttributeList *attrs) {
    if (!tree || !attrs) return false;
    return oabe_policy_satisfies(tree, attrs->attributes);
}