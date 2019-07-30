#!/usr/bin/perl

use v5.16;

my $party = $ARGV[0] or die "party required";
my $nrecords = $ARGV[1] or die "num records required";

my %ssns;

for (my $i=0; $i < $nrecords; $i++) {
    my $ssn;
    while (1) {
        $ssn = sprintf "%03d-%02d-%04d", rand(1000), rand(100), rand(10000);
        if (not $ssns{$ssn}) {
            $ssns{$ssn} = 1;
            last;
        }
    }

    if ($party eq "receiver") {
        say $ssn;
        next;
    }

    my $pl1 = rand(1000);
    my $pl2 = rand(1000);
    my $pl3 = rand(1000);

    my @letters = ('a'..'z', 'A'..'Z', '0'..'9');
    my $pl4 = $letters[rand(@letters)] for 0..23;

    say "$ssn, $pl1, $pl2, $pl3, $pl4";
}
