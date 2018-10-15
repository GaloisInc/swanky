#!/usr/bin/env perl

use strict;
use v5.10;
use POSIX;

my ($mode, $nbits, $base) = @ARGV;

my $n = ceil(log(2**$nbits) / log($base)); 

if ($mode eq "tab") {
    print_table();
    exit;
} elsif ($mode eq "num") {
    say $n;
    exit;
} else {
    die "unknown mode!";
}

sub digits_base {
    my ($x, $base) = @_;
    my @ds;
    while ($x >= $base) {
        my $d = $x % $base;
        push @ds, $d;
        $x = ($x - $d) / $base;
    }
    push @ds, $x;
    while (@ds < $n) {
        push @ds, 0;
    }
    return @ds;
}

sub print_table {
    printf "const uint8_t BASE_%d [][%d] = {\n", $base, $n;
    my $end = 2**$nbits;
    my $line = "";
    for (my $x = 0; $x < $end; $x++) {
        my @ds = digits_base($x, $base);
        $line .= "{" . join(",", map{sprintf("0x%02X",$_)}@ds) . "}";
        if ($x < $end - 1) {
            $line .= ", ";
        }
        if (length $line > 100) {
            say "    $line";
            $line = "";
        }
    }
    if (length $line > 0) {
        print "    $line";
    }
    print "\n};\n";
}
