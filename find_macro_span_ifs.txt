egrep -rn "if\( .*\)" -A1 library | egrep -B1 '#(else|endif)'
