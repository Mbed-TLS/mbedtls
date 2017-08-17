
/* Create code coverage job */
def get_code_coverage_job(){
    return {
        node('linux') {
            checkout scm
            sh "./tests/scripts/basic-build-test.sh"
        }
    }
}

/* Jenkinsfile interface to this script. */
def dispatch_job() {
    parallel_jobs = []
    parallel_jobs['code_coverage'] = get_code_coverage_job();
    parallel parallel_jobs
}

/* Required for load statement in Jenkinsfile */
return this
