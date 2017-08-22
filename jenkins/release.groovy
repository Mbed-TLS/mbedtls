
/* Create code coverage job */
def get_code_coverage_job(){
    return {
        node('linux') {
            unstash 'src'
            sh "./tests/scripts/basic-build-test.sh"
        }
    }
}

def get_all_sh_job(){
    return {
        node('linux') {
            unstash 'src'
            sh "./tests/scripts/all.sh"
        }
    }
}

def find_examples (){
    examples = []
    File[] files = new File(pwd()).listFiles();
    for (File file: files){
        if (file.isDirectory()) {
            File[] subfiles = file.listFiles();
            for (File subfile: subfiles){
                if (subfile.getName().equals("mbed-os.lib")) {
                    examples << file.getName()
                }
            }
        }
    }
    return examples;
}


def checkout_mbed_os_examples(){
    dir('examples'){
        git 'git@github.com:ARMmbed/mbed-os-example-tls.git'
        def examples = find_examples()
        stash 'examples_src'
        /* checkout mbed-os */
        echo examples.join(", ")
        def oneexample = examples[0]
        echo oneexample
        if ( oneexample != null ) {
            dir( oneexample ){
                git 'git@github.com:ARMmbed/mbed-os.git'
                sh '''
sha=`cut -d "#" -f 2 ../mbed-os.lib`
git reset --hard $sha
'''
                dir('mbed-os'){
                    /* Deploy mbedtls src into mbed-os */
                    dir('features/mbedtls/importer') {
                        dir('TARGET_IGNORE/mbedtls'){
                            unstash('src')
                        }
                        sh 'make all'
                    }
                    stash 'mbed-os_src'
                }
            }
            return examples;
        }
    }
    return []
}

def gen_mbed_os_example_job( example, compiler, platform ){
    return {
       node( compiler ){
            timestamps {
                deleteDir()
                unstash "examples_src"
                dir( example ){
                    unstash "mbed-os_src"
                    sh """
mbed config root .
mbed compile -m ${platform} -t ${toolchain}
"""
                }
            }
       }
   }
}

compilers = ['ARM', 'GCC_ARM', 'IAR']
platforms = ['K64F']

/* Jenkinsfile interface to this script. */
def dispatch_job() {
    /* Checkout mbed-os-example-tls */
    parallel_jobs = [:]
    parallel_jobs['code_coverage'] = get_code_coverage_job();
    example = checkout_mbed_os_examples()
    for( example in examples ) {
        for( compiler in compilers ) {
            for( platform in platforms ) {
                parallel_jobs["${example}-${platform}-${compiler}"] =
                    gen_mbed_os_example_job(example, compiler, platform)
            }
        }
    }
    parallel parallel_jobs
}

/* Required for load statement in Jenkinsfile */
return this
