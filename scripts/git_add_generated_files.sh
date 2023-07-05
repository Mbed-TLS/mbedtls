cd $(dirname ${BASH_SOURCE[0]})
cd ..
git reset .
git clean -Xfd
make generated_files
git ls-files -oi --exclude-standard | git add -f --pathspec-from-file=-
git ls-files -ci --exclude="*.pyc" | git reset --pathspec-from-file=-