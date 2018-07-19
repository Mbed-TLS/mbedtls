#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"

/* There are different GET_HASH macros for different kinds of algorithms
 * built from hashes, but the values are all constructed on the
 * same model. */
#define PSA_ALG_GET_HASH(alg)                                   \
    (((alg) & PSA_ALG_HASH_MASK) | PSA_ALG_CATEGORY_HASH)

static void append(char **buffer, size_t buffer_size,
                   size_t *required_size,
                   const char *string, size_t length)
{
    *required_size += length;
    if (*required_size < buffer_size) {
        memcpy(*buffer, string, length);
        *buffer += length;
    }
}

/* The code of these function is automatically generated and included below. */
static const char *psa_ecc_curve_name(psa_ecc_curve_t curve);
static const char *psa_hash_algorithm_name(psa_algorithm_t hash_alg);

static void append_with_curve(char **buffer, size_t buffer_size,
                              size_t *required_size,
                              const char *string, size_t length,
                              psa_ecc_curve_t curve)
{
    const char *curve_name = psa_ecc_curve_name(curve);
    append(buffer, buffer_size, required_size, string, length);
    append(buffer, buffer_size, required_size, "(", 1);
    if (curve_name != NULL) {
        append(buffer, buffer_size, required_size,
               curve_name, strlen(curve_name));
    } else {
        size_t n = snprintf(*buffer, buffer_size - *required_size,
                            "0x%04x", (unsigned) curve);
        if (n < buffer_size - *required_size) *buffer += n;
        *required_size += n;
    }
    append(buffer, buffer_size, required_size, ")", 1);
}

static void append_with_hash(char **buffer, size_t buffer_size,
                             size_t *required_size,
                             const char *string, size_t length,
                             psa_algorithm_t hash_alg)
{
    const char *hash_name = psa_hash_algorithm_name(hash_alg);
    append(buffer, buffer_size, required_size, string, length);
    append(buffer, buffer_size, required_size, "(", 1);
    if (hash_name != NULL) {
        append(buffer, buffer_size, required_size,
               hash_name, strlen(hash_name));
    } else {
        size_t n = snprintf(*buffer, buffer_size - *required_size,
                            "0x%08lx", (unsigned long) hash_alg);
        if (n < buffer_size - *required_size) *buffer += n;
        *required_size += n;
    }
    append(buffer, buffer_size, required_size, ")", 1);
}

#include "psa_constant_names_generated.c"

static int psa_snprint_status(char *buffer, size_t buffer_size,
                              psa_status_t status)
{
    const char *name = psa_strerror(status);
    if (name == NULL) {
        return snprintf(buffer, buffer_size, "%ld", (long) status);
    } else {
        size_t length = strlen(name);
        if (length < buffer_size) {
            memcpy(buffer, name, length + 1);
            return length;
        } else {
            return buffer_size;
        }
    }
}

static int psa_snprint_ecc_curve(char *buffer, size_t buffer_size,
                                 psa_ecc_curve_t curve)
{
    const char *name = psa_ecc_curve_name(curve);
    if (name == NULL) {
        return snprintf(buffer, buffer_size, "0x%04x", (unsigned) curve);
    } else {
        size_t length = strlen(name);
        if (length < buffer_size) {
            memcpy(buffer, name, length + 1);
            return length;
        } else {
            return buffer_size;
        }
    }
}

static void usage(const char *program_name)
{
    printf("Usage: %s TYPE VALUE\n",
           program_name == NULL ? "psa_constant_names" : program_name);
    printf("Print the symbolic name whose numerical value is VALUE in TYPE.\n");
    printf("Supported types (with = between aliases):\n");
    printf("  alg=algorithm         Status code (psa_algorithm_t)\n");
    printf("  curve=ecc_curve       Elliptic curve identifier (psa_ecc_curve_t)\n");
    printf("  type=key_type         Status code (psa_key_type_t)\n");
    printf("  usage=key_usage       Key usage (psa_key_usage_t)\n");
    printf("  error=status          Status code (psa_status_t)\n");
}

int main(int argc, char *argv[])
{
    char buffer[200];
    unsigned long value;
    char *end;

    if (argc <= 1 ||
        !strcmp(argv[1], "help") ||
        !strcmp(argv[1], "--help"))
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (argc != 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    value = strtoul(argv[2], &end, 0);
    if (*end) {
        printf("Non-numeric value: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "error") || !strcmp(argv[1], "status"))
        psa_snprint_status(buffer, sizeof(buffer), value);
    else if (!strcmp(argv[1], "alg") || !strcmp(argv[1], "algorithm"))
        psa_snprint_algorithm(buffer, sizeof(buffer), value);
    else if (!strcmp(argv[1], "curve") || !strcmp(argv[1], "ecc_curve"))
        psa_snprint_ecc_curve(buffer, sizeof(buffer), value);
    else if (!strcmp(argv[1], "type") || !strcmp(argv[1], "key_type"))
        psa_snprint_key_type(buffer, sizeof(buffer), value);
    else if (!strcmp(argv[1], "usage") || !strcmp(argv[1], "key_usage"))
        psa_snprint_key_usage(buffer, sizeof(buffer), value);
    else {
        printf("Unknown type: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    puts(buffer);
    return EXIT_SUCCESS;
}
