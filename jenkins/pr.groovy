
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

cmake_asan_test_sh = """
cmake -D CMAKE_BUILD_TYPE:String=Asan .
make clean
make
make test
./programs/test/selftest
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
                //label = "${platform} && mbedtls"
                node( platform ){
                    timestamps {
                        def compiler_path = compiler_paths[compiler]
                            unstash 'src'
                            script =  """
CC=${compiler_path}
""" + script
                            sh script
                    }
                }
            }
        }
    }
    return jobs
}

def gen_batch_jobs_foreach ( label, platforms, compilers, script ){
    jobs = [:]

    for ( platform in platforms ){
        for ( compiler in compilers ){
            jobs["${label}-${compiler}-${platform}"] = {
                node( platform ){
                    def compiler_path = compiler_paths[compiler]
                    unstash 'src'
                    bat script
                }
            }
        }
    }
    return jobs
}

/* main job */
node {
    def linux_platforms = [ "ecs-debian-x32", "ecs-debian-x64" ]
    def bsd_platforms = [ "freebsd" ]
    def bsd_compilers = [ "gcc48" ]
    def windows_platforms = ['windows']
    def windows_compilers = ['cc']
    def all_compilers = ['gcc', 'clang']
    def gcc_compilers = ['gcc']
    def asan_compilers = ['clang']

    checkout([$class: 'GitSCM', branches: [[name: 'refs/heads/jenkinsfile']],
            doGenerateSubmoduleConfigurations: false,
            extensions: [[$class: 'CloneOption', honorRefspec: true,
            noTags: true, reference: '', shallow: true]],
            submoduleCfg: [],
            userRemoteConfigs: [[credentialsId: "${env.GIT_CREDENTIALS_ID}",
            url: "${env.MBEDTLS_REPO}"]]])
    stash 'src'

    /* Linux jobs */
    def jobs = gen_jobs_foreach( 'std-make', linux_platforms, all_compilers, std_make_test_sh )
    jobs = jobs + gen_jobs_foreach( 'cmake', linux_platforms, all_compilers, cmake_test_sh )
    jobs = jobs + gen_jobs_foreach( 'cmake-full', linux_platforms, gcc_compilers, cmake_full_test_sh )
    jobs = jobs + gen_jobs_foreach( 'cmake-asan', linux_platforms, asan_compilers, cmake_asan_test_sh )

    /* BSD jobs */
    jobs = jobs + gen_jobs_foreach( 'gmake', bsd_platforms, bsd_compilers, gmake_test_sh )
    jobs = jobs + gen_jobs_foreach( 'cmake', bsd_platforms, bsd_compilers, cmake_test_sh )

    /* Windows jobs */
    /* Uncomment once windows slaves are added.
    jobs = jobs + gen_batch_jobs_foreach( 'win32-mingw', windows_platforms, windows_compilers, mingw_cmake_test_bat )
    jobs = jobs + gen_batch_jobs_foreach( 'win32_msvc12_32', windows_platforms, windows_compilers, win32_msvc12_32_test_bat )
    jobs = jobs + gen_batch_jobs_foreach( 'win32_msvc12_64', windows_platforms, windows_compilers, win32_msvc12_64_test_bat )
    */

    parallel jobs
}

