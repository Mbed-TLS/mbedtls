project('mbedtls', 'c', license: 'apache-2.0')

cc =  meson.get_compiler('c')
id = cc.get_id()
if id == 'gcc'
	add_project_arguments('-Wmissing-declarations', '-Wmissing-prototypes', language: 'c')
elif id == 'clang'
	add_project_arguments('-Wmissing-declarations', '-Wmissing-prototypes', '-Wdocumentation', '-Wno-documentation-deprecated-sync', '-Wunreachable-code', language: 'c')
endif

subdir('library')
