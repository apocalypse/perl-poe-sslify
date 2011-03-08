#!/usr/bin/perl

# Thanks to ASCENT for this test!

use strict; use warnings;

my $numtests;
BEGIN {
	$numtests = 8;

	eval "use Test::NoWarnings";
	if ( ! $@ ) {
		# increment by one
		$numtests++;
	}
}

use Test::More tests => $numtests;

use POE 1.267;
use POE::Component::Client::TCP;
use POE::Component::Server::TCP;
use POE::Component::SSLify qw/Client_SSLify SSLify_GetSocket SSLify_GetStatus/;

# TODO rewrite this to use Test::POE::Server::TCP and stuff :)

my $port;

POE::Component::Server::TCP->new
(
	Alias			=> 'myserver',
	Address			=> '127.0.0.1',
	Port			=> 0,

	Started			=> sub
	{
		use Socket qw/sockaddr_in/;
		$port = (sockaddr_in($_[HEAP]->{listener}->getsockname))[0];
	},
	ClientConnected		=> sub
	{
		ok(1, 'SERVER: accepted');
	},
	ClientDisconnected	=> sub
	{
		ok(1, 'SERVER: client disconnected');
		$_[KERNEL]->post( 'myserver' => 'shutdown');
	},
	ClientInput		=> sub
	{
		my ($kernel, $heap, $line) = @_[KERNEL, HEAP, ARG0];

		# purposefully send garbage so we screw up the ssl connect on the client-side
		$heap->{client}->put( 'garbage in, garbage out' );
	},
	ClientError	=> sub
	{
		# Thanks to H. Merijn Brand for spotting this FAIL in 5.12.0!
		# The default PoCo::Server::TCP handler will throw a warning, which causes Test::NoWarnings to FAIL :(
		my ($syscall, $errno, $error) = @_[ ARG0..ARG2 ];

		# Since this test purposefully sends garbage, we expect a connection reset by peer
		# not ok 7 - Got SERVER read error 104: Connection reset by peer

		# TODO are there other "errors" that is harmless?
		$error = "Normal disconnection" unless $error;
		my $msg = "Got SERVER $syscall error $errno: $error";
		unless ( $syscall eq 'read' and $errno == 104 ) {
			fail( $msg );
		} else {
			diag( $msg ) if $ENV{TEST_VERBOSE};
		}
	},
);

POE::Component::Client::TCP->new
(
	Alias		=> 'myclient',
	RemoteAddress	=> '127.0.0.1',
	RemotePort	=> $port,
	Connected	=> sub
	{
		ok(1, 'CLIENT: connected');
	},
	PreConnect	=> sub
	{
		my $socket = eval { Client_SSLify($_[ARG0], sub {
			my( $socket, $status, $errval ) = @_;

			pass( "CLIENT: Got connect hook" );
			is( $status, 'ERR', "CLIENT: Status received from callback is ERR - $errval" );

			$poe_kernel->post( 'myclient' => 'shutdown' );
		}) };
		ok(!$@, "CLIENT: Client_SSLify $@");
		ok( SSLify_GetStatus($socket) == -1, "CLIENT: SSLify_GetStatus is pending" );

		return ($socket);
	},
	ServerInput	=> sub
	{
		my ($kernel, $heap, $line) = @_[KERNEL, HEAP, ARG0];

		die "Should have never got any input from the server!";
	},
	ServerError	=> sub
	{
		# Thanks to H. Merijn Brand for spotting this FAIL in 5.12.0!
		# The default PoCo::Client::TCP handler will throw a warning, which causes Test::NoWarnings to FAIL :(
		my ($syscall, $errno, $error) = @_[ ARG0..ARG2 ];

		# TODO are there other "errors" that is harmless?
		$error = "Normal disconnection" unless $error;
		my $msg = "Got CLIENT $syscall error $errno: $error";
		unless ( $syscall eq 'read' and $errno == 0 ) {
			fail( $msg );
		} else {
			diag( $msg ) if $ENV{TEST_VERBOSE};
		}
	},
);

$poe_kernel->run();

pass( 'shut down sanely' );

exit 0;
