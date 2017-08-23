
std_make_test_sh = """
make clean
make
make check
./programs/test/selftest
"""

gmake_test_sh = """
gmake clean
gmake
gmake check
./programs/test/selftest
"""

cmake_test_sh = """
cmake -D CMAKE_BUILD_TYPE:String=Check .
make clean
make
make test
./programs/test/selftest
"""

cmake_full_test_sh = cmake_test_sh + """
./tests/compat.sh
./tests/ssl-opt.sh
./tests/scripts/test-ref-configs.pl
"""

mingw_cmake_test_bat = """
cmake . -G MinGW Makefiles
mingw32-make clean
mingw32-make
mingw32-make test
programs\\test\\selftest.exe
"""

win32_msvc12_32_test_bat = """
cmake . -G Visual Studio 12
MSBuild ALL_BUILD.vcxproj
"""

win32_msvc12_64_test_bat = """
cmake . -G Visual Studio 12 Win64
MSBuild ALL_BUILD.vcxproj
"""

compiler_paths = [
    'gcc' : '/usr/bin/gcc',
    'gcc48' : '/usr/local/bin/gcc48',
    'clang' : '/usr/bin/clang',
    'cc' : 'cc'
]

def gen_jobs_foreach ( label, platforms, compilers, script ){
    jobs = [:]

    for ( platform in platforms ){
        for ( compiler in compilers ){
            jobs["${label}-${compiler}-${platform}"] = {
                node( platform ){
                    def compiler_path = compiler_paths[compiler]
                    script =  """
CC=${compiler_path}
""" + script
                    sh script
                }
            }
        }
    }
}

def gen_batch_jobs_foreach ( label, platforms, compilers, script ){
    jobs = [:]

    for ( platform in platforms ){
        for ( compiler in compilers ){
            jobs["${label}-${compiler}-${platform}"] = {
                node( platform ){
                    def compiler_path = compiler_paths[compiler]
                    bat script
                }
            }
        }
    }
}

/* Jenkinsfile interface to this script. */
def dispatch_job(){
    linux_platforms = [ "debian-wheezy-i386", "debian-wheezy-amd64" ]
    bsd_platforms = [ "freebsd-9-i386" ]
    bsd_compilers = [ "gcc48" ]
    windows_platforms = ['windows']
    windows_compilers = ['cc']
    all_compilers = ['gcc', 'clang']

    /* Linux jobs */
    def jobs = gen_jobs_foreach( 'std-make', linux_platforms, all_compilers, std_make_test_sh )
    jobs = jobs + gen_jobs_foreach( 'cmake', linux_platforms, all_compilers, cmake_test_sh )
    jobs = jobs + gen_jobs_foreach( 'cmake-full', linux_platforms, all_compilers, cmake_full_test_sh )

    /* BSD jobs */
    jobs = jobs + gen_jobs_foreach( 'gmake', bsd_platforms, bsd_compilers, gmake_test_sh )
    jobs = jobs + gen_jobs_foreach( 'cmake', bsd_platforms, bsd_compilers, cmake_test_sh )

    /* Windows jobs */
    jobs = jobs + gen_batch_jobs_foreach( 'win32-mingw', windows_platforms, windows_compilers, mingw_cmake_test_sh )
    jobs = jobs + gen_batch_jobs_foreach( 'win32_msvc12_32', windows_platforms, windows_compilers, win32_msvc12_32_test_bat )
    jobs = jobs + gen_batch_jobs_foreach( 'win32_msvc12_64', windows_platforms, windows_compilers, win32_msvc12_64_test_bat )

    parallel jobs
}

/* Required for load statement in Jenkinsfile */
return this

