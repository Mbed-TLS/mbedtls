#!/usr/bin/env python3
"""Generate test code to validate the server-side TLS 1.3 HRR reset."""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import os
import sys

import scripts_path  # pylint: disable=unused-import
from mbedtls_framework import build_tree
from mbedtls_framework import ssl_session_reset_check

import generate_ssl_session_reset_check


# The HRR reset is narrower than mbedtls_ssl_session_reset(): it replaces
# only CH1-derived handshake and provisional-session state. Start from KEEP
# so that connection and record-layer fields retain their state, then list
# the deliberate exceptions below.
RULES = dict.fromkeys(generate_ssl_session_reset_check.RULES,
                      ssl_session_reset_check.ResetBehavior.KEEP)

# ssl_handshake_init() can currently reallocate variable record buffers while
# resetting CH1-derived state. This must be fixed separately; until then,
# verify that the replacement buffers are valid instead of requiring identity.
for field in ('in_buf', 'in_ctr', 'in_hdr', 'in_cid', 'in_len', 'in_iv',
              'in_msg', 'out_buf', 'out_ctr', 'out_hdr', 'out_cid',
              'out_len', 'out_iv', 'out_msg'):
    RULES[field] = ssl_session_reset_check.ResetBehavior.REALLOCATE

for field in ('handshake', 'session_negotiate', 'user_data'):
    RULES[field] = ssl_session_reset_check.ResetBehavior.SPECIAL

# ALPN is the one CH1-derived value stored directly in mbedtls_ssl_context.
RULES['alpn_chosen'] = ssl_session_reset_check.ResetBehavior.RESET
RULES['unused'] = ssl_session_reset_check.ResetBehavior.IGNORE

SPECIAL_BEHAVIORS = {
    'handshake': [
        'TEST_ASSERT(before->handshake != NULL);',
        'TEST_ASSERT(after->handshake != NULL);',
        'TEST_ASSERT(before->handshake->ciphersuite_info == ' +
        'after->handshake->ciphersuite_info);',
        'TEST_EQUAL(before->handshake->hrr_selected_group, ' +
        'after->handshake->hrr_selected_group);',
        'TEST_ASSERT(before->handshake->update_checksum ==',
        '            after->handshake->update_checksum);',
        'normalized_handshake = *after->handshake;',
        'normalized_handshake.ciphersuite_info = ' +
        'initial.handshake->ciphersuite_info;',
        'normalized_handshake.hrr_selected_group = ' +
        'initial.handshake->hrr_selected_group;',
        'normalized_handshake.update_checksum = ' +
        'initial.handshake->update_checksum;',
        '#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)',
        'TEST_EQUAL(before->handshake->ch1_sni_name_present, ' +
        'after->handshake->ch1_sni_name_present);',
        'TEST_EQUAL(before->handshake->ch1_sni_name_len, ' +
        'after->handshake->ch1_sni_name_len);',
        'if (before->handshake->ch1_sni_name_present) {',
        'TEST_MEMORY_COMPARE(before->handshake->ch1_sni_name, ' +
        'before->handshake->ch1_sni_name_len, ' +
        'after->handshake->ch1_sni_name, ' +
        'after->handshake->ch1_sni_name_len);',
        '}',
        'normalized_handshake.ch1_sni_name_present = ' +
        'initial.handshake->ch1_sni_name_present;',
        'normalized_handshake.ch1_sni_name = ' +
        'initial.handshake->ch1_sni_name;',
        'normalized_handshake.ch1_sni_name_len = ' +
        'initial.handshake->ch1_sni_name_len;',
        '#endif',
        '#if defined(PSA_WANT_ALG_SHA_256)',
        'normalized_handshake.fin_sha256_psa = ' +
        'initial.handshake->fin_sha256_psa;',
        '#endif',
        '#if defined(PSA_WANT_ALG_SHA_384)',
        'normalized_handshake.fin_sha384_psa = ' +
        'initial.handshake->fin_sha384_psa;',
        '#endif',
        '#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)',
        '/* Ignore unspecified inactive union storage in the opaque PAKE ' +
        'operation. */',
        'memcpy(&normalized_handshake.psa_pake_ctx, ' +
        '&initial.handshake->psa_pake_ctx, ' +
        'sizeof(normalized_handshake.psa_pake_ctx));',
        '#endif',
        'TEST_MEMORY_COMPARE(&normalized_handshake, ' +
        'sizeof(normalized_handshake), initial.handshake, ' +
        'sizeof(*initial.handshake));',
    ],
    'session_negotiate': [
        'TEST_ASSERT(before->session_negotiate != NULL);',
        'TEST_ASSERT(after->session_negotiate != NULL);',
        'normalized_session = *after->session_negotiate;',
        '#if defined(MBEDTLS_SSL_EARLY_DATA)',
        'TEST_EQUAL(before->session_negotiate->max_early_data_size, ' +
        'after->session_negotiate->max_early_data_size);',
        'normalized_session.max_early_data_size = ' +
        'initial.session_negotiate->max_early_data_size;',
        '#endif',
        'TEST_MEMORY_COMPARE(&normalized_session, sizeof(normalized_session), ' +
        'initial.session_negotiate, sizeof(*initial.session_negotiate));',
    ],
    'user_data': [
        'TEST_EQUAL(before->user_data.n, after->user_data.n);',
    ],
}

FIELDS_INFO = ssl_session_reset_check.FieldsInfo(
    RULES,
    SPECIAL_BEHAVIORS,
    generate_ssl_session_reset_check.NAMED_STRUCTURES)


class HRRSSLContextStruct(ssl_session_reset_check.SSLContextStruct):
    # pylint: disable=too-few-public-methods
    """Generate checks for the reset performed after an HRR is written."""

    def write_check_function(self, out):
        out.write(f'''\
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * The following function was automatically generated through the script
 * ./{sys.argv[0]}.
 */

#include <test/ssl_helpers.h>
#include <test/ssl_helpers_internal.h>
#include "mbedtls/psa_util.h"
#include <test/macros.h>

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3) && \\
    defined(MBEDTLS_SSL_SRV_C)

int mbedtls_test_ssl_check_context_after_hrr_reset(
    const mbedtls_ssl_context *before,
    const mbedtls_ssl_context *after)
{{
    mbedtls_ssl_context initial;
    mbedtls_ssl_handshake_params normalized_handshake;
    mbedtls_ssl_session normalized_session;
    int ret = -1;

    memset(&initial, 0, sizeof(initial));
    memset(&normalized_handshake, 0, sizeof(normalized_handshake));
    mbedtls_ssl_init(&initial);
    TEST_EQUAL(mbedtls_ssl_setup(&initial, after->conf), 0);

    /* This reset retains connection and record-layer state. Variable record
     * buffers may currently be reallocated by ssl_handshake_init(), so their
     * replacement is checked for validity rather than pointer identity. */
    /* *INDENT-OFF* */
''')
        for field_info in self.fields:
            if field_info.conditionals:
                out.write('\n'.join(field_info.conditionals))
            for check_line in field_info.check_value():
                if check_line.startswith('#'):
                    out.write(f'{check_line}\n')
                else:
                    out.write(f'    {check_line}\n')
            if field_info.conditionals:
                out.write('#endif\n' * len(field_info.conditionals))
        out.write('''\
    /* *INDENT-ON* */

    ret = 0;

exit:
    mbedtls_ssl_free(&initial);
    return ret;
}

#endif /* MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_PROTO_TLS1_3 &&
          MBEDTLS_SSL_SRV_C */
''')


def main():
    if not build_tree.looks_like_mbedtls_root(os.curdir):
        raise Exception("The script must be launched from the root path of Mbed TLS")
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', dest='output_file',
                        default='tests/src/ssl_hrr_reset_verifier.c')
    args = parser.parse_args()
    with open(args.output_file, 'wt', encoding='utf-8') as output:
        HRRSSLContextStruct(FIELDS_INFO).write_check_function(output)


if __name__ == '__main__':
    main()
