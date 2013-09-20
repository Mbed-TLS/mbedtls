#!/usr/bin/perl

# create individual project files for example programs
# for VS6 and VS2010

use warnings;
use strict;

my $vs6_dir = "../visualc/VS6";
my $vs6_ext = "dsp";
my $vs6_template_file = "data_files/vs6-app-template.$vs6_ext";

my $vsx_dir = "../visualc/VS2010";
my $vsx_ext = "vcxproj";
my $vsx_template_file = "data_files/vs2010-app-template.$vsx_ext";

exit( main() );

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
    my $app_list = `cd ../programs && make list`;
    die "make list failed: $!\n" if $?;

    return split /\s+/, $app_list;
}

sub main {
    -d $vs6_dir || die "VS6 directory not found: $vs6_dir\n";
    -d $vsx_dir || die "VS2010 directory not found: $vsx_dir\n";

    my $vs6_tpl = slurp_file( $vs6_template_file );
    my $vsx_tpl = slurp_file( $vsx_template_file );

    for my $app ( get_app_list() ) {
        printf "$app\n";
        gen_app( $app, $vs6_tpl, $vs6_dir, $vs6_ext );
        gen_app( $app, $vsx_tpl, $vsx_dir, $vsx_ext );
    }

    return 0;
}
