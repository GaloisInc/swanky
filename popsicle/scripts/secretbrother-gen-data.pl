#!/usr/bin/perl

use v5.16;

my $party = $ARGV[0];
my $nrecords = $ARGV[1];

for (my $i=0; $i < $nrecords; $i++) {
    printf "%03d-%02d-%04d", rand(1000), rand(100), rand(10000);

    if ($party eq "receiver") {
        say;
        next;
    }

    print ", ";
    print join ", ", rand(1000), rand(1000), rand(1000);
    print ", ";
    my @letters = ('a'..'z', 'A'..'Z', ' '); 
    print $letters[rand(@letters)] for 0..23;
    say;
}
