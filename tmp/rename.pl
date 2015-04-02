#!/usr/bin/perl

use warnings;
use strict;

use utf8;
use open qw(:std utf8);

# apply substitutions from the table in the first arg to files
#   expected usage: via invoke-rename.pl

die "Usage: $0 names-file [filenames...]\n" if( @ARGV < 1 or ! -r $ARGV[0] );

open my $nfh, '<', shift or die;
my @names = <$nfh>;
close $nfh or die;

my %subst;
for my $name (@names) {
    chomp $name;
    my ($old, $new) = split / /, $name;
    $subst{$old} = $new;
}

my $string = qr/".*?(?<!\\)"/;
my $space = qr/\s+/;
my $idnum = qr/[a-zA-Z0-9_]+/;
my $symbols = qr/[!#%&'()*+,-.:;<=>?@^_`{|}~\$\/\[\\\]]+|"/;

my %warnings;

while( my $filename = shift )
{
    print STDERR "$filename... ";
    if( -d $filename ) { print STDERR "skip (directory)"; next }

    open my $rfh, '<', $filename or die;
    my @lines = <$rfh>;
    close $rfh or die;

    my @out;
    for my $line (@lines) {
        my @words = ($line =~ /$string|$space|$idnum|$symbols/g);
        my $checkline = join '', @words;
        if( $checkline eq $line ) {
            my @new = map { exists $subst{$_} ? $subst{$_} : $_ } @words;
            push( @out, join '', @new );
        } else {
            $warnings{$filename} = [] unless $warnings{$filename};
            push @{ $warnings{$filename} }, $line;
            push( @out, $line );
        }
    }

    open my $wfh, '>', $filename or die;
    print $wfh $_ for @out;
    close $wfh or die;
    print STDERR "done\n";
}

if( %warnings ) {
    print "\nWarning: lines skipped due to unexpected charaacters:\n";
    for my $filename (sort keys %warnings) {
        print "in $filename:\n";
        print for @{ $warnings{$filename} };
    }
}
