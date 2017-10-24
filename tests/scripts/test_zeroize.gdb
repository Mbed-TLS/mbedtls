set confirm off
file ./programs/test/zeroize
break zeroize.c:90

set args ./programs/test/zeroize.c
run

set $i = 0
set $len = sizeof(buf)
set $buf = buf

if exit_code != 0
    echo The program did not terminate correctly\n
    quit 1
end

while $i < $len
    if $buf[$i++] != 0
        echo The buffer at was not zeroized\n
        quit 1
    end
end

echo The buffer was correctly zeroized\n
quit 0
