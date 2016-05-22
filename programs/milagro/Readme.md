
**********************************************************

TA_cs and TA_p2p simulate the trusted authorities, the
will generate the client and server's secrets.  

tls_client.c and tls_server.c have as default the
ciphersuite TLS-MILAGRO-CS-WITH-AES-128-GCM-SHA256.
to force the Milagro_p2p ciphersuite the command is:

$ tls_server.c = force_ciphersuite=TLS-MILAGRO-P2P-WITH-AES-128-GCM-SHA256
$ tls_client.c = force_ciphersuite=TLS-MILAGRO-P2P-WITH-AES-128-GCM-SHA256

