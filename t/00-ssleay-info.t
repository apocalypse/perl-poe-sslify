#!/usr/bin/perl
use strict; use warnings;

# displays some basic info

use Test::FailWarnings;
use Test::More 1.001002; # new enough for sanity in done_testing()

use POE::Component::SSLify;

# only available > 1.42
eval {
	diag( "\nNet::SSLeay::ver_number is 0x" . sprintf( "%x", Net::SSLeay::SSLeay() ) );
	diag( "\t" . Net::SSLeay::SSLeay_version( 0 ) );
	diag( "\t" . Net::SSLeay::SSLeay_version( 2 ) );
	diag( "\t" . Net::SSLeay::SSLeay_version( 3 ) );
	diag( "\t" . Net::SSLeay::SSLeay_version( 4 ) );
};

# Idea taken from POE t/00_info.t :)
my $done = 0;
my $x    = 0;
$SIG{ALRM} = sub { diag "\tpogomips: $x"; $done = 1; };
alarm(1);
++$x until $done;

ok(1, "fake test for info");
done_testing;
