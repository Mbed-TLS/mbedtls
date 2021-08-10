#!/usr/bin/env python3

"""Mbed TLS trace post-processor

Compile with -DMBEDTLS_TRACE and -DMBEDTLS_DEBUG_C. Capture the output to
a log file and pass it to this post processor. It is designed to generate
a table of which primitives are used in which handshake stages, and how
many bytes are used per context (if applicable).
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may
## not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
## WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

import sys
import re
import json

class CAliasTable:
    """ Provides context to alias mapping """
    def __init__ (self):
        self.current_alias = 0
        self.context_to_alias = {}
        self.alias_to_context = {}
        self.alias_description = {}
    def base_add (self, key):
        self.context_to_alias[key] = self.current_alias
        self.alias_to_context[self.current_alias] = key
        self.alias_description[self.current_alias] = "unknown"
        self.current_alias = self.current_alias + 1
    def add (self, trace):
        ctx = trace['ctx']
        if ctx in self.context_to_alias:
            raise Exception("Context already in use, cannot alias: %s" % ctx)
        self.base_add(ctx)
    def remove (self, trace):
        ctx = trace['ctx']
        if ctx in self.context_to_alias:
            del self.context_to_alias[ctx]
        else:
            print("Warning: freeing context without clone/init: %s" % ctx)
    def clone (self, trace):
        src = trace['ctx']
        dst = trace['ctx2']
        if dst in self.context_to_alias:
            print("Warning: cloning existing context: %s into %s" % (src, dst))
        self.base_add(dst)
    def get_alias (self, context):
        if context in self.context_to_alias:
            return self.context_to_alias[context]
        return None
    def get_context (self, alias):
        if alias in self.alias_to_context:
            return self.alias_to_context[alias]
        return None
    def description (self, alias, description=None):
        if description:
            self.alias_description[alias] = description
        elif alias in self.alias_description:
            return self.alias_description[alias]
        return None



class CTraceProcessor:
    """ Processes an mbedTLS TRACE file. """
    def __init__(self):
        self.aliases = CAliasTable()
        self.current_state = -1
        self.scoreboard = {}
        self.block_sha = False

    def process_file(self, file_name):
        with open(file_name, 'r') as file:
            for line in file:
                self.process_line(line.strip())

    def process_line(self, line):
        # See: ./library/ssl_cli.c: MBEDTLS_SSL_DEBUG_MSG( 2, ( "client state
        m = re.match(r'.*client state: (\d+)', line)
        if m:
            self.current_state = int(m[1])
        else:
            if re.match(r'^trace{', line):
                self.process_one_trace(re.sub(r'^trace', '', line))

    def process_one_trace(self, text):
        """ Call the correct parse based on the type of trace """
        trace = json.loads(text)
        if 'prim' not in trace and 'op' not in trace:
            raise Exception("No 'prim' or 'op' in: %s" % trace)
        if 'prim' in trace:
            self.process_known_op(trace)
        else:
            self.process_unknown_op(trace)

    def process_known_op (self, trace):
        """ Known ops have init/free and handlers """
        # First update the alias table with the context
        op = trace['op']
        if op == 'init':
            self.aliases.add(trace)
        elif op == 'clone':
            self.aliases.clone(trace)
        elif op == 'free':
            self.aliases.remove(trace)
        # Now handle the primitive
        functable = {
            'aes'    : self.process_block_cipher,
            'ccm'    : self.process_block_cipher,
            'gcm'    : self.process_block_cipher,
            'sha256' : self.process_digest,
            'ecdh'   : self.process_key_exchange,
            'ecdsa'  : self.process_sign_verify,
        }
        prim = trace['prim']
        if prim not in functable:
            raise Exception("No handler is implemented for %s" % prim)
        functable[prim](trace)

    def process_block_cipher (self, trace):
        """ All block ciphers have a context, nubmer of bytes, and ENC/DEC """
        op = trace['op']
        if op in ('encrypt', 'decrypt'):
            ctx = trace['ctx']
            num_bytes = trace['bytes']
            alias = self.aliases.get_alias(ctx)
            small_op = '/E' if op == 'encrypt' else '/D'
            self.post_event(alias, num_bytes, trace['prim'] + small_op)

    def process_digest (self, trace):
        """ Digests only have a context & byte count of interest """
        suffix = ""
        if self.block_sha is True:
            suffix = "/ECDSA+DROP"
        op = trace['op']
        if op == 'update':
            ctx = trace['ctx']
            num_bytes = trace['bytes']
            alias = self.aliases.get_alias(ctx)
            self.post_event(alias, num_bytes, trace['prim'] + suffix)

    def process_key_exchange (self, trace):
        """ Key exchange only cares about a context """
        op = trace['op']
        if op == 'calc_secret':
            ctx = trace['ctx']
            alias = self.aliases.get_alias(ctx)
            self.post_event(alias, 1, trace['prim'])

    def process_sign_verify (self, trace):
        """ Sign/verify only cares about context """
        op = trace['op']
        m = re.match(r'^(read|write)_signature', op)
        if m:
            # Don't consider SHA operations inside sign/verify
            self.block_sha = True
            ctx = trace['ctx']
            alias = self.aliases.get_alias(ctx)
            self.post_event(alias, 1, m[1])
        if re.match(r'.*EXIT', op):
            self.block_sha = False

    def process_unknown_op(self, trace):
        """ These are leftover ops that don't have a clear parse strategy, in
        other words they are hacks that don't have a clear plan yet."""
        op = trace['op']
        if op == 'block_cipher_df-1' or op == 'block_cipher_df-2':
            self.hack_operation('b', trace['ctx'], op)
        elif op == 'mbedtls_ctr_drbg_random_with_add':
            self.hack_operation('r', trace['ctx2'], op)
        elif op == 'ctr_drbg_update_internal':
            self.hack_operation('u', trace['ctx2'], op)
        else:
            raise Exception("Unknown operation %s" % op)

    def hack_operation (self, prefix, ctx, op):
        """ These are mbedTLS functions that uses a previous AES context, but we
        need a unique reference to it so that the operations don't overload.
        If we don't add the prefix, the bytes used by the wrapper operations
        get added to the reference context, which is exactly the opposite of
        what we want. And if we use the same prefix, we miss the individual
        wrapper functions. This is painfully complex."""
        key = prefix + "/" + ctx
        alias = self.aliases.get_alias(key)
        if alias is None:
            self.aliases.base_add(key)
            alias = self.aliases.get_alias(key)
        self.post_event(alias, 16, "%s/AES+SUBTRACT" % op[0:10])

    def post_event (self, alias, n, tag):
        """ Add an event to the scoreboard, incrementing its 'n' value. """
        self.aliases.description(alias, tag)
        if alias not in self.scoreboard:
            self.scoreboard[alias] = {}
        slot = self.scoreboard[alias]
        if self.current_state in slot:
            slot[self.current_state] += n
        else:
            slot[self.current_state] = n



def main ():
    if len(sys.argv) < 2:
        raise Exception("Please specify the input file to process.")
    trace_processor = CTraceProcessor()
    trace_processor.process_file(sys.argv[1])

    print("% 5s,% 30s,% 15s:," % ("alias", "type", "context"), end="")
    for i in range (-1, 20):
        print("% 5d," % i, end="")
    print("")

    for alias in sorted(trace_processor.scoreboard):
        print("%05d,% 30s,% 16s," % (
            int(alias),
            trace_processor.aliases.description(alias),
            trace_processor.aliases.get_context(alias)),
            end="")
        for i in range(-1, 20):
            if i in trace_processor.scoreboard[alias]:
                print("% 5s," % str(
                    trace_processor.scoreboard[alias][i]), end="")
            else:
                print("% 5s," % " ", end="")
        print()

if __name__ == '__main__':
    main()
