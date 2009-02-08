#!/usr/bin/perl
use strict; use warnings;

my $numtests;
BEGIN {
	$numtests = 3;

	eval "use Test::NoWarnings";
	if ( ! $@ ) {
		# increment by one
		$numtests++;

	}
}

use Test::More tests => $numtests;

use_ok( 'POE::Component::SSLify::ServerHandle' );
use_ok( 'POE::Component::SSLify::ClientHandle' );
use_ok( 'POE::Component::SSLify' );