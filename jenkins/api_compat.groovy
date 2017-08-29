
def dump_abi(slave_label, repo, branch, version){
    node( slave_label ){
        git branch: branch, url: repo
        dir( branch ) {
            sh """
cmake -DCMAKE_BUILD_TYPE:String=Check -DUSE_SHARED_MBEDTLS_LIBRARY=On .
abi-dumper library/libmbedtls.so -o ABI.dump -lver ${branch}
"""
        }
    }
}

/* Run API/ABI compatibility test */
node( "${env.SLAVE_LABEL}" ){
    def slave_label = "${env.SLAVE_LABEL}"
    def old_repo = "${env.SRC_REPO}"
    def old_branch = "${env.SRC_BRANCH}"
    def old_ver = "${env.SRC_VERSION}"
    def new_repo = "${env.DST_REPO}"
    def new_branch = "${env.DST_BRANCH}"
    def new_ver = "${env.DST_VERSION}"
    dump_abi( slave_label, old_repo, src_branch, src_ver )
    dump_abi( slave_label, new_repo, dst_branch, dst_ver )
    sh """
abi-compliance-checker -l mbedtls -old ${old_branch}/ABI.dump -new ${new_branch}/ABI.dump
"""
    publishHTML([allowMissing: false, alwaysLinkToLastBuild: false, keepAll: false, reportDir: "compat_reports/mbedtls/${old_branch}_to_${new_branch}", reportFiles: 'compat_report.html', reportName: 'API/ABI Compatibility Report', reportTitles: ''])
}

/* Required for load statement in Jenkinsfile */
return this

