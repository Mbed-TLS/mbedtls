This prototype is to give a tangible understanding of the proposal.
The base template file driver_wrapper_sample.conf is a stripped down version of the psa_crypto_driver_wrapper.c file.
The said template file serves to hold some of the existing fixed components(legacy support and builtin functionality) in place while rendering templates for driver specific support.

Prototype nomenclature

Driver json file: example_driver.json -> This is a compilation of the driver capabilities present on the device.

Driver json config :driver_capability_config.json -> This is a fixed DB of capabilities against configurable definitions. Serves as a lookup table to define the configurable set of accelerated algorithms to mute out the same as built in components. sample_config.h serves as such an auto generated header file which needs to be included into config_psa.h

Template Files
OS-template-transparent.conf: One shot transparent driver template
OS-template-opaque.conf     : One shot opaque driver template
MP-template-setup.conf      : Multi part setup template
MP-template-continue.conf   : Multi part continue template
 
Generated file: driver_wrapper_sample.c is a sample generated file which would finally be the psa_crypto_driver_wrapper.c file.

generate.py: Master python script

A few disclaimers:
The Prototype does not consider a few cases like, haveing multiple capability entries for a given "entry_point", configurations based on "key_type" and options for custom names.
