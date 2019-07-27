#!/usr/bin/env perl
# Backward compatibility redirection
my $py = $0;
$py =~ s/\.pl$/.py/;
exec 'python3', $py, @ARGV
