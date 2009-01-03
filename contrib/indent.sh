#!/bin/sh

indent --blank-lines-after-declarations         \
       --blank-lines-after-procedures           \
       --swallow-optional-blank-lines           \
       --blank-lines-before-block-comments      \
       --format-all-comments                    \
       --format-first-column-comments           \
       --comment-delimiters-on-blank-lines      \
       --start-left-side-of-comments            \
       --braces-after-if-line                   \
       --braces-after-struct-decl-line          \
       --brace-indent 0                         \
       --dont-cuddle-else                       \
       --dont-cuddle-do-while                   \
       --case-indentation 4                     \
       --case-brace-indentation 0               \
       --dont-space-special-semicolon           \
       --no-space-after-function-call-names     \
       --no-space-after-casts                   \
       --no-space-after-for                     \
       --no-space-after-if                      \
       --no-space-after-while                   \
       --space-after-parentheses                \
       --no-blank-lines-after-commas            \
       --break-function-decl-args               \
       --dont-break-function-decl-args-end      \
       --dont-break-procedure-type              \
       --indent-level 4                         \
       --continue-at-parentheses                \
       "$@"

