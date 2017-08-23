import groovy.io.FileType

/* Create code coverage job */
def get_code_coverage_job(){
    return {
        node('linux') {
            deleteDir()
            unstash 'src'
            sh "./tests/scripts/basic-build-test.sh"
        }
    }
}

def get_all_sh_job(){
    return {
        node('linux') {
            deleteDir()
            unstash 'src'
            sh "./tests/scripts/all.sh"
        }
    }
}

def find_examples (){
    examples = []
    File[] files = new File(pwd()).listFiles();
    for (File file: files){
        echo file.getName()
        if (file.isDirectory()) {
            echo 'Is dir'
            File[] subfiles = file.listFiles();
            for (File subfile: subfiles){
                echo subfile.getName()
                if (subfile.getName().equals("mbed-os.lib")) {
                    echo file.getName()
                    examples << file.getName()
                }
            }
        }
    }
    return ['authcrypt', 'benchmark', 'hashing', 'tls-client'];
}


def checkout_mbed_os_examples(){
    def examples = []
    dir('examples'){
        git 'git@github.com:ARMmbed/mbed-os-example-tls.git'
        examples = find_examples()
        stash 'examples_src'
        /* checkout mbed-os */
        echo examples.join(", ")
        def oneexample = examples[0]
        echo oneexample
        if ( oneexample != null ) {
            dir( oneexample ){
                dir('mbed-os'){
                    git 'git@github.com:ARMmbed/mbed-os.git'
                    sh '''
sha=`cut -d "#" -f 2 ../mbed-os.lib`
git reset --hard $sha
'''
                    /* Deploy mbedtls src into mbed-os */
                    dir('features/mbedtls/importer') {
                        dir('TARGET_IGNORE/mbedtls'){
                            echo pwd()
                            unstash('src')
                            sh 'ls -ltr'
                        }
                        sh 'make all'
                    }
                    stash 'mbed-os_src'
                }
            }
        }
    }
    return examples
}

def gen_mbed_os_example_job( example, compiler, platform ){
    return {
       node( compiler ){
            timestamps {
                deleteDir()
                unstash "examples_src"
                dir( example ){
                    dir('mbed-os'){
                        unstash "mbed-os_src"
                    }
                    sh """
mbed config root .
mbed compile -m ${platform} -t ${compiler}
export RAAS_USERNAME=user
export RAAS_PASSWORD=user
export RAAS_PYCLIENT_FORCE_REMOTE_ALLOCATION=1
export RAAS_PYCLIENT_ALLOCATION_QUEUE_TIMEOUT=3600
mbedhtrun -m ${platform} -g raas_client:54.194.213.112:8000 -P 600 -v --compare-log ../tests/${example}.log -f BUILD/${platform}/${compiler}/${example}.bin
"""
                }
            }
       }
   }
}

//compilers = ['ARM', 'GCC_ARM', 'IAR']
compilers = ['GCC_ARM']
platforms = ['K64F']

/* Jenkinsfile interface to this script. */
def dispatch_job() {
    /* Checkout mbed-os-example-tls */
    parallel_jobs = [:]
    //parallel_jobs['code_coverage'] = get_code_coverage_job();
    examples = checkout_mbed_os_examples()
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
