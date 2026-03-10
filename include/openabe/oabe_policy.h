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
/// \file   oabe_policy.h
///
/// \brief  Policy parsing and Linear Secret Sharing Scheme (LSSS) for OpenABE C.
///

#ifndef OABE_POLICY_H
#define OABE_POLICY_H

#include "oabe_types.h"
#include "oabe_memory.h"
#include "oabe_bytestring.h"
#include "oabe_zml.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Policy Node Types
 *============================================================================*/

/**
 * Policy node type - leaf or internal node.
 */
typedef enum {
    OABE_POLICY_LEAF = 0,       /* Leaf node (attribute) */
    OABE_POLICY_AND = 1,        /* AND gate */
    OABE_POLICY_OR = 2,         /* OR gate */
    OABE_POLICY_THRESHOLD = 3   /* Threshold gate (k-of-n) */
} OABE_PolicyNodeType;

/**
 * Threshold operator type.
 */
typedef enum {
    OABE_THRESHOLD_OFN = 0,     /* Threshold of N */
    OABE_THRESHOLD_ALL = 1      /* All of N (N-of-N) */
} OABE_ThresholdType;

/*============================================================================
 * Policy Tree Structures
 *============================================================================*/

/**
 * Forward declaration of policy node.
 */
typedef struct OABE_PolicyNode OABE_PolicyNode;

/**
 * Policy node structure - represents a node in the policy tree.
 */
struct OABE_PolicyNode {
    OABE_Object base;
    OABE_PolicyNodeType type;           /* Node type */
    char *attribute;                     /* Attribute name (for leaf nodes) */
    int threshold;                       /* Threshold value (for internal nodes) */
    OABE_PolicyNode **children;          /* Child nodes */
    size_t num_children;                 /* Number of children */
    int *sat_list;                       /* Satisfaction list (for secret sharing) */
    size_t sat_list_len;                 /* Length of satisfaction list */
};

/**
 * Policy tree structure.
 */
typedef struct OABE_PolicyTree {
    OABE_Object base;
    OABE_PolicyNode *root;               /* Root node of the policy tree */
    size_t num_leaves;                   /* Number of leaf nodes */
    OABE_StringVector *attributes;        /* List of all attributes */
} OABE_PolicyTree;

/*============================================================================
 * Policy Parsing Functions
 *============================================================================*/

/**
 * Parse a policy string into a policy tree.
 * Policy format: "attr1 and attr2", "(attr1 or attr2) and attr3", etc.
 * @param policy Policy string
 * @param tree Output policy tree (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_policy_parse(const char *policy, OABE_PolicyTree **tree);

/**
 * Free a policy tree.
 * @param tree Policy tree
 */
void oabe_policy_tree_free(OABE_PolicyTree *tree);

/**
 * Clone a policy tree.
 * @param tree Policy tree to clone
 * @return Cloned policy tree, or NULL on failure
 */
OABE_PolicyTree* oabe_policy_tree_clone(const OABE_PolicyTree *tree);

/**
 * Get all attributes from a policy tree.
 * @param tree Policy tree
 * @param attrs Output string vector (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_policy_get_attributes(const OABE_PolicyTree *tree, OABE_StringVector **attrs);

/**
 * Check if an attribute is in the policy.
 * @param tree Policy tree
 * @param attr Attribute name
 * @return true if attribute is in policy, false otherwise
 */
bool oabe_policy_has_attribute(const OABE_PolicyTree *tree, const char *attr);

/**
 * Serialize a policy tree to ByteString.
 * @param tree Policy tree
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_policy_serialize(const OABE_PolicyTree *tree, OABE_ByteString **result);

/**
 * Deserialize a policy tree from ByteString.
 * @param input Input ByteString
 * @param tree Output policy tree (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_policy_deserialize(const OABE_ByteString *input, OABE_PolicyTree **tree);

/**
 * Convert policy tree to string representation.
 * @param tree Policy tree
 * @return String representation (caller must free), or NULL on failure
 */
char* oabe_policy_to_string(const OABE_PolicyTree *tree);

/**
 * Check if a set of attributes satisfies the policy tree.
 * For CP-ABE: Check if the user's attributes can satisfy the policy.
 * For KP-ABE: Check if the policy can be satisfied by the ciphertext attributes.
 * @param tree Policy tree
 * @param attributes String vector of attribute names
 * @return true if attributes satisfy the policy, false otherwise
 */
bool oabe_policy_satisfies(const OABE_PolicyTree *tree, const OABE_StringVector *attributes);

/*============================================================================
 * Attribute List Functions
 *============================================================================*/

/**
 * Attribute list structure.
 */
typedef struct OABE_AttributeList {
    OABE_Object base;
    OABE_StringVector *attributes;       /* List of attribute strings */
} OABE_AttributeList;

/**
 * Create a new attribute list.
 * @return Attribute list, or NULL on failure
 */
OABE_AttributeList* oabe_attr_list_new(void);

/**
 * Create an attribute list from a comma-separated string.
 * @param attr_str Comma-separated attributes (e.g., "attr1,attr2,attr3")
 * @return Attribute list, or NULL on failure
 */
OABE_AttributeList* oabe_attr_list_from_string(const char *attr_str);

/**
 * Free an attribute list.
 * @param list Attribute list
 */
void oabe_attr_list_free(OABE_AttributeList *list);

/**
 * Clone an attribute list.
 * @param list Attribute list to clone
 * @return Cloned attribute list, or NULL on failure
 */
OABE_AttributeList* oabe_attr_list_clone(const OABE_AttributeList *list);

/**
 * Add an attribute to the list.
 * @param list Attribute list
 * @param attr Attribute to add
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_attr_list_add(OABE_AttributeList *list, const char *attr);

/**
 * Remove an attribute from the list.
 * @param list Attribute list
 * @param attr Attribute to remove
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_attr_list_remove(OABE_AttributeList *list, const char *attr);

/**
 * Check if an attribute is in the list.
 * @param list Attribute list
 * @param attr Attribute to check
 * @return true if attribute is in list, false otherwise
 */
bool oabe_attr_list_contains(const OABE_AttributeList *list, const char *attr);

/**
 * Get the number of attributes.
 * @param list Attribute list
 * @return Number of attributes
 */
size_t oabe_attr_list_get_count(const OABE_AttributeList *list);

/**
 * Get an attribute by index.
 * @param list Attribute list
 * @param index Index
 * @return Attribute string, or NULL if out of bounds
 */
const char* oabe_attr_list_get(const OABE_AttributeList *list, size_t index);

/**
 * Serialize an attribute list to ByteString.
 * @param list Attribute list
 * @param result Output ByteString (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_attr_list_serialize(const OABE_AttributeList *list, OABE_ByteString **result);

/**
 * Deserialize an attribute list from ByteString.
 * @param input Input ByteString
 * @param list Output attribute list (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_attr_list_deserialize(const OABE_ByteString *input, OABE_AttributeList **list);

/**
 * Check if a set of attributes satisfies the policy tree using an attribute list.
 * @param tree Policy tree
 * @param attrs Attribute list
 * @return true if attributes satisfy the policy, false otherwise
 */
bool oabe_policy_satisfies_list(const OABE_PolicyTree *tree, const OABE_AttributeList *attrs);

/*============================================================================
 * Linear Secret Sharing Scheme (LSSS)
 *============================================================================*/

/**
 * LSSS matrix structure.
 * Used for CP-ABE secret sharing.
 */
typedef struct OABE_LSSSMatrix {
    OABE_Object base;
    int **matrix;                       /* The LSSS matrix */
    size_t rows;                        /* Number of rows */
    size_t cols;                        /* Number of columns */
    OABE_StringVector *row_labels;       /* Attribute labels for each row */
} OABE_LSSSMatrix;

/**
 * Create a new LSSS matrix from a policy tree.
 * @param tree Policy tree
 * @param matrix Output LSSS matrix (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_lsss_from_policy(const OABE_PolicyTree *tree, OABE_LSSSMatrix **matrix);

/**
 * Free an LSSS matrix.
 * @param matrix LSSS matrix
 */
void oabe_lsss_matrix_free(OABE_LSSSMatrix *matrix);

/**
 * Compute secret shares using LSSS matrix.
 * @param matrix LSSS matrix
 * @param secret Secret value to share
 * @param shares Output array of shares (caller must free)
 * @param shares_len Output length of shares array
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_lsss_share(const OABE_LSSSMatrix *matrix, const OABE_ZP *secret,
                           OABE_ZP ***shares, size_t *shares_len);

/**
 * Recover secret from shares using LSSS matrix.
 * @param matrix LSSS matrix
 * @param shares Array of shares
 * @param shares_len Length of shares array
 * @param indices Array of row indices corresponding to satisfied attributes
 * @param indices_len Length of indices array
 * @param secret Output recovered secret (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_lsss_recover(const OABE_LSSSMatrix *matrix, OABE_ZP **shares,
                              size_t shares_len, const int *indices, size_t indices_len,
                              OABE_ZP **secret);

/**
 * Get row label for a specific row.
 * @param matrix LSSS matrix
 * @param row Row index
 * @return Attribute label, or NULL if out of bounds
 */
const char* oabe_lsss_get_row_label(const OABE_LSSSMatrix *matrix, size_t row);

/**
 * Share a secret through a policy tree using polynomial secret sharing.
 * This is the proper implementation matching the original OpenABE algorithm.
 * @param policy Policy tree root node
 * @param secret Secret value to share
 * @param rng RNG handle for random polynomial coefficients
 * @param shares Output array of shares (caller must free with oabe_lsss_free_coefficients)
 * @param attributes Output array of attribute labels (caller must free)
 * @param count Output number of shares
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_lsss_share_tree(OABE_PolicyNode *policy, OABE_ZP *secret,
                                 OABE_RNGHandle rng,
                                 OABE_ZP ***shares, char ***attributes, size_t *count);

/**
 * Recover Lagrange coefficients for decryption.
 * Given a policy and user attributes, compute the coefficients needed to
 * combine shares for secret recovery.
 * @param policy Policy tree root node
 * @param user_attrs User's attribute list
 * @param group Group handle
 * @param coefficients Output array of coefficients (caller must free)
 * @param attributes Output array of attribute labels (caller must free)
 * @param count Output number of coefficients
 * @return OABE_SUCCESS or error code, OABE_ERROR_POLICY_NOT_SATISFIED if policy not satisfied
 */
OABE_ERROR oabe_lsss_recover_coefficients(OABE_PolicyNode *policy,
                                            OABE_StringVector *user_attrs,
                                            OABE_GroupHandle group,
                                            OABE_ZP ***coefficients,
                                            char ***attributes,
                                            size_t *count);

/**
 * Free coefficient arrays from oabe_lsss_share_tree or oabe_lsss_recover_coefficients.
 * @param coefficients Coefficient array
 * @param attributes Attribute array
 * @param count Number of elements
 */
void oabe_lsss_free_coefficients(OABE_ZP **coefficients, char **attributes, size_t count);

/**
 * Evaluate a polynomial at a given point.
 * Polynomial: P(x) = coefficients[0] + coefficients[1]*x + coefficients[2]*x^2 + ...
 * @param group Group handle
 * @param coefficients Array of polynomial coefficients (coefficient[0] is constant term)
 * @param num_coeff Number of coefficients
 * @param x Point at which to evaluate (integer)
 * @param result Output result (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_evaluate_polynomial(OABE_GroupHandle group, OABE_ZP **coefficients,
                                    size_t num_coeff, int x, OABE_ZP **result);

/**
 * Compute Lagrange coefficient for interpolation at x=0.
 * L_i(0) = prod_{j != i, j in indices} (-indices[j]) / (indices[i] - indices[j])
 * @param group Group handle
 * @param index The index for which to compute the coefficient (must be in indices array)
 * @param indices Array of all x-coordinates (1-based, i.e., 1, 2, 3, ...)
 * @param num_indices Number of indices
 * @param result Output coefficient (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_compute_lagrange(OABE_GroupHandle group, int index, int *indices,
                                 size_t num_indices, OABE_ZP **result);

/*============================================================================
 * Function Input (Policy or Attribute List)
 *============================================================================*/

/**
 * Function input type.
 */
typedef enum {
    OABE_INPUT_POLICY = 0,       /* Input is a policy */
    OABE_INPUT_ATTRIBUTES = 1    /* Input is an attribute list */
} OABE_FunctionInputType;

/**
 * Function input structure.
 * Can represent either a policy or an attribute list.
 */
typedef struct OABE_FunctionInput {
    OABE_Object base;
    OABE_FunctionInputType type;         /* Input type */
    union {
        OABE_PolicyTree *policy;         /* Policy tree (if type == OABE_INPUT_POLICY) */
        OABE_AttributeList *attrs;       /* Attribute list (if type == OABE_INPUT_ATTRIBUTES) */
    } data;
} OABE_FunctionInput;

/**
 * Create a function input from a string.
 * Automatically detects if it's a policy or attribute list.
 * @param input Input string
 * @param func_input Output function input (caller must free)
 * @return OABE_SUCCESS or error code
 */
OABE_ERROR oabe_function_input_parse(const char *input, OABE_FunctionInput **func_input);

/**
 * Free a function input.
 * @param func_input Function input
 */
void oabe_function_input_free(OABE_FunctionInput *func_input);

/**
 * Get the type of function input.
 * @param func_input Function input
 * @return Input type
 */
OABE_FunctionInputType oabe_function_input_get_type(const OABE_FunctionInput *func_input);

/**
 * Get the policy tree (if input is a policy).
 * @param func_input Function input
 * @return Policy tree, or NULL if input is not a policy
 */
OABE_PolicyTree* oabe_function_input_get_policy(const OABE_FunctionInput *func_input);

/**
 * Get the attribute list (if input is an attribute list).
 * @param func_input Function input
 * @return Attribute list, or NULL if input is not an attribute list
 */
OABE_AttributeList* oabe_function_input_get_attributes(const OABE_FunctionInput *func_input);

#ifdef __cplusplus
}
#endif

#endif /* OABE_POLICY_H */