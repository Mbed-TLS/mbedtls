Rename mbedtls_*_ret() cryptography functions whose deprecated variants have been removed in #4029
--

This change affects users who were using the `mbedtls_*_ret()` criptography functions.

Those functions were created based on now-deprecated functions according to a
requirement that a function needs to return a value. This change brings back the
original names of those functions.

To migrate to the this change the user can keep the `*_ret` names in their code
and include the `compat_2.x.h` header file which holds macros with proper
renaming or to rename those function in their code according to the list from
mentioned header file.
