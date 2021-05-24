Remove the mode parameter from RSA functions
--------------------------------------------

This affects all users who use the RSA encryption, decryption, sign and
verify APIs.

You must delete the mode parameter from your RSA function calls.
Using the correct modes are now the default and only behaviour, and this
cannot be changed. If you were using the mode parameter to specify the
wrong mode then this behaviour is no longer supported. For reference the
correct, supported modes are: Public keys for encryption and verification
functions and private keys for decryption and signing functions, but the
user does not have to specify this.

Remove the RNG parameter from RSA functions
--------------------------------------------

This affects all users who use the RSA verify functions.

If you were using the RNG parameters then you must remove
them from your function calls. Since using the wrong mode
is no longer supported, the RNG parameters namely f_rng
and p_rng are no longer needed.
