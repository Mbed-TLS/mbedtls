#!/usr/bin/perl

# activate a pre-defined configuration

use warnings;
use strict;

my $config_h = "../include/polarssl/config.h";

exit( main() );

sub read_default {
    open my $fh, '<', $config_h or die "Failed to read $config_h: $!\n";

    my (@pre, @post);
    my $state = 'pre';

    while( my $line = <$fh> ) {
        if( $state eq 'pre' ) {
            push @pre, $line;
            $state = 'skip' if $line =~ /} name SECTION: System support/;
        }
        elsif( $state eq 'skip' ) {
            $state = 'post' if $line =~/} name SECTION: PolarSSL modules/;
        }
        else {
            push @post, $line;
        }
    }

    die "Failed to parse $config_h\n" if( $state ne 'post' );

    close $fh;

    push @pre, "\n";

    return \@pre, \@post;
}

sub read_custom {
    my ($file_name) = @_;

    open my $fh, '<', $file_name or die "Failed to read $file_name: $!\n";
    my @content = <$fh>;
    close $fh;

    return \@content;
}

sub write_custom {
    my ($pre, $mid, $post) = @_;

    open my $fh, '>', $config_h or die "Failed to write $config_h: $!\n";
    print $fh @$pre;
    print $fh @$mid;
    print $fh @$post;
    close $fh;
}

sub main {
    my $custom_file_name = $ARGV[0];

    my ($pre, $post) = read_default();
    my $mine = read_custom( $custom_file_name );
    write_custom( $pre, $mine, $post );

    return 0;
}
