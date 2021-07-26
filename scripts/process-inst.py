#!/usr/bin/env python3

"""Mbed TLS instrumentation post-processor

Compile with -DMBEDTLS_INST and -DMBEDTLS_DEBUG_C. Capture the output to
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

if len(sys.argv) < 2:
    raise Exception("Please specify the input file to process.")

file = open(sys.argv[1], 'r')

# We use this global to ignore all SHA operations when inside ECDSA
# mbedtls uses SHA in our config, so it is a hack to remove misleading
# SHA operations that are implementation-specific.
FENCE_shablock = False

current_state = -1

class CAliasTable:
    def __init__ (self):
        self.index = 0
        self.table = {}
        self.rtable = {}
        self.purposes = {}
    def _add (self, key):
        self.table[key] = self.index
        self.rtable[self.index] = key
        self.purposes[self.index] = "unknown"
        self.index = self.index + 1
    def add (self, instance):
        ctx = instance['ctx']
        #print('add %s' % ctx)
        if ctx in self.table:
            raise Exception("Context already in use, cannot alias: %s" % ctx)
        else:
            self._add(ctx)
    def remove (self, instance):
        ctx = instance['ctx']
        #print('remove %s' % ctx)
        if ctx in self.table:
            del self.table[ctx]
        else:
            print("Warning: freeing context without clone/init: %s" % ctx)
    def clone (self, instance):
        src = instance['ctx']
        dst = instance['ctx2']
        #print("clone %s -> %s" % (src, dst))
        if dst in self.table:
            print("Warning: cloning into existing context: %s into %s" % (src, dst))
        self._add(dst)
    def id (self, ctx):
        return self.table[ctx] if ctx in self.table else None
    def ctx (self, id):
        return self.rtable[id] if id in self.rtable else None
    def purpose (self, id, purpose=None):
        if purpose:
            self.purposes[id] = purpose
        else:
            return self.purposes[id] if id in self.purposes else None

scoreboard = {}

aliases = CAliasTable()

def post_event (id, n, tag):
    aliases.purpose(id, tag)
    if id not in scoreboard:
        scoreboard[id] = {}
    slot = scoreboard[id]
    if current_state in slot:
        slot[current_state] += n
    else:
        slot[current_state] = n

# Since contexts may be reused by an init after a free, we need to alias each
# context, when it is seen, by using the CAliasTable class.
def update_contexts (instance):
    op = instance['op']
    if op == 'init':
        aliases.add(instance)
    elif op == 'clone':
        aliases.clone(instance)
    elif op == 'free':
        aliases.remove(instance)

def process_block_cipher (instance):
    op = instance['op']
    if op == 'encrypt' or op == 'decrypt':
        ctx = instance['ctx']
        bytes = instance['bytes']
        id = aliases.id(ctx)
        smallop = '/E' if op == 'encrypt' else '/D'
        post_event(id, bytes, instance['prim'] + smallop)

def process_digest (instance):
    global FENCE_shablock
    suffix = ""
    if FENCE_shablock == True:
        suffix = "/ECDSA+DROP"
    op = instance['op']
    if op == 'update':
        ctx = instance['ctx']
        bytes = instance['bytes']
        id = aliases.id(ctx)
        post_event(id, bytes, instance['prim'] + suffix)

def process_key_exchange (instance):
    op = instance['op']
    if op == 'calc_secret':
        ctx = instance['ctx']
        id = aliases.id(ctx)
        post_event(id, 1, instance['prim'])

def process_sign_verify (instance):
    global FENCE_shablock
    op = instance['op']
    m = re.match(r'^(read|write)_signature', op)
    if m:
        FENCE_shablock = True
        ctx = instance['ctx']
        id = aliases.id(ctx)
        post_event(id, 1, m[1])
    if re.match(r'.*EXIT', op):
        FENCE_shablock = False

functable = {
    'aes'    : process_block_cipher,
    'ccm'    : process_block_cipher,
    'gcm'    : process_block_cipher,
    'sha256' : process_digest,
    'ecdh'   : process_key_exchange,
    'ecdsa'  : process_sign_verify,
}

def process_prim (instance):
    update_contexts(instance)
    prim = instance['prim']
    if prim not in functable:
        raise Exception("No handler is implemented for %s" % prim)
    functable[prim](instance)

def hackop (prefix, ctx, op):
    # These are mbedTLS functions that uses a previous AES context, but we
    # need a unique reference to it so that the operations don't overload.
    # If we don't add the prefix, the bytes used by the wrapper operations
    # get added to the reference context, which is exaclty the opposite of
    # what we want. And if we use the same prefix, we miss the individual
    # wrapper functions. This is painfully complex.
    #
    # TODO: Excluding auxilliary AES operations is too complicated
    key = prefix + "/" + ctx
    id = aliases.id(key)
    if id == None:
        aliases._add(key)
        id = aliases.id(key)
    post_event(id, 16, "%s/AES+SUBTRACT" % op[0:10])

# These ops are wrappers that call AES functions for things other than
# encrypting/decrypting, e.g., random number generation. This is specific
# to mbedTLS.
def process_generic_op (instance):
    op = instance['op']
    if op == 'block_cipher_df-1' or op == 'block_cipher_df-2':
        hackop('b', instance['ctx'], op)
    elif op == 'mbedtls_ctr_drbg_random_with_add':
        hackop('r', instance['ctx2'], op)
    elif op == 'ctr_drbg_update_internal':
        hackop('u', instance['ctx2'], op)

def process_inst (line):
    raw = re.sub(r'^inst', '', line)
    inst = json.loads(raw)
    #print(">", raw)
    # Sanity check.
    if 'prim' not in inst and 'op' not in inst:
        raise Exception("No 'prim' or 'op' in: %s" % inst)
    # Primitives have a context; update context aliases
    if 'prim' in inst:
        process_prim(inst)
    else:
        # These aren't primitives, they are wrapper functions that do weird
        # things and need to be parsed so that we can modify/clean up the
        # counts.
        process_generic_op(inst)

for line in file:
    line = line.strip();
    m = re.match(r'.*client state: (\d+)', line)
    if m:
        current_state = int(m[1])
    else:
        if re.match(r'^inst{', line):
            process_inst(line)

#print(scoreboard)
print("% 5s,% 30s,% 15s:," % ("alias", "type", "context"), end="")
for i in range (-1, 20):
    print("% 5d," % i, end="")
print("")

for id in sorted(scoreboard):
    print("%05d,% 30s,% 16s," % (int(id), aliases.purpose(id), aliases.ctx(id)), end="")
    for i in range(-1, 20):
        if i in scoreboard[id]:
            print("% 5s," % str(scoreboard[id][i]), end="")
        else:
            print("% 5s," % " ", end="")
    print()
