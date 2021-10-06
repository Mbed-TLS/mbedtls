#!/usr/bin/env perl

use Time::HiRes;

if (@ARGV == 0 || $ARGV[0] eq '--help') {
    print <<EOF;
Usage: $0 COMMAND [ARGS...]
Run a program and prefix timestamps to its output.
Also print a final timestamped line with the program's exit status, and
exit with that code (with signals wrapped to 128+signum).
The program's stderr and stdout are merged into stdout.
Relay common signals to the program.
EOF
      exit;
}

sub ts {
    my ($t, $us) = Time::HiRes::gettimeofday();
    my ($s, $m, $h, @_ignored) = gmtime($t);
    printf '%05d.%06d %s', $s + $m*60 + $h*24*60, $us, $_[0];
}

local (*IN, *OUT);
pipe IN, OUT;
if (my $pid = fork()) {
    $SIG{'INT'} = $SIG{'TERM'} = $SIG{'HUP'} = $SIG{'QUIT'} = sub {
        kill($_[0], $pid);
    };
    close OUT;
    $| = 1;
    while (<IN>) {
        ts($_);
    }
    wait;
    ts(join(' ', @ARGV, "==> $?\n"));
    exit($? & 127 ? 128 + ($? & 127) : $? >> 8);
} else {
    open STDOUT, '>&OUT';
    open STDERR, '>&OUT';
    close OUT;
    close IN;
    exec('stdbuf', '-o0', @ARGV);
    print STDERR "$!\n";
    exit 127;
}
