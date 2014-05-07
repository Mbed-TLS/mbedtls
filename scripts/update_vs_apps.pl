#!/usr/bin/perl

# create individual project files for example programs
# for VS6 and VS2010
#
# Must be run from PolarSSL root or scripts directory.
# Takes no argument.

use warnings;
use strict;

my $vs6_dir = "visualc/VS6";
my $vs6_ext = "dsp";
my $vs6_app_tpl_file = "scripts/data_files/vs6-app-template.$vs6_ext";

my $vsx_dir = "visualc/VS2010";
my $vsx_ext = "vcxproj";
my $vsx_app_tpl_file = "scripts/data_files/vs2010-app-template.$vsx_ext";

my $programs_dir = 'programs';

exit( main() );

sub check_dirs {
    return -d $vs6_dir
        && -d $vsx_dir
        && -d $programs_dir;
}

sub slurp_file {
    my ($filename) = @_;

    local $/ = undef;
    open my $fh, '<', $filename or die "Could not read $filename\n";
    my $content = <$fh>;
    close $fh;

    return $content;
}

sub gen_app {
    my ($path, $template, $dir, $ext) = @_;

    $path =~ s!/!\\!g;
    (my $appname = $path) =~ s/.*\\//;

    my $content = $template;
    $content =~ s/<PATHNAME>/$path/g;
    $content =~ s/<APPNAME>/$appname/g;

    open my $app_fh, '>', "$dir/$appname.$ext";
    print $app_fh $content;
    close $app_fh;
}

sub get_app_list {
    my $app_list = `cd $programs_dir && make list`;
    die "make list failed: $!\n" if $?;

    return split /\s+/, $app_list;
}

sub gen_app_files {
    my $vs6_tpl = slurp_file( $vs6_app_tpl_file );
    my $vsx_tpl = slurp_file( $vsx_app_tpl_file );

    for my $app ( get_app_list() ) {
        gen_app( $app, $vs6_tpl, $vs6_dir, $vs6_ext );
        gen_app( $app, $vsx_tpl, $vsx_dir, $vsx_ext );
    }
}

sub main {
    if( ! check_dirs() ) {
        chdir '..' or die;
        check_dirs or die "Must but run from PolarSSL root or scripts dir\n";
    }

    print "Generating apps files: ";
    gen_app_files();
    print "done.\n";

    return 0;
}
