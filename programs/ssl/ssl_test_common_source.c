/*
 *  Common source code for SSL test programs. This file is included by
 *  both ssl_client2.c and ssl_server2.c and is intended for source
 *  code that is textually identical in both programs, but that cannot be
 *  compiled separately because it refers to types or macros that are
 *  different in the two programs, or because it would have an incomplete
 *  type.
 *
 *  This file is meant to be #include'd and cannot be compiled separately.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
