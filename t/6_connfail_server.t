#!/usr/bin/perl
use strict; use warnings;

# this tests the connection fail hook on the server-side

my $numtests;
BEGIN {
	$numtests = 8;

#	eval "use Test::NoWarnings";
#	if ( ! $@ ) {
#		# increment by one
#		$numtests++;
#	}
}

# For some reason I can't get this to replicate 5_connfail_client.t - wonder why?!#?
# I tried to use POE::Filter::Stream to see if it made a difference, nope...
#use Test::More tests => $numtests;
use Test::More;
plan skip_all => "This test hangs for some reason";

use POE 1.267;
use POE::Component::Client::TCP;
use POE::Component::Server::TCP;
use POE::Component::SSLify qw/Server_SSLify SSLify_Options SSLify_GetSocket SSLify_GetStatus/;

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
	ClientPreConnect	=> sub
	{
		eval { SSLify_Options('mylib/example.key', 'mylib/example.crt') };
		eval { SSLify_Options('../mylib/example.key', '../mylib/example.crt') } if ($@);
		ok(!$@, "SERVER: SSLify_Options $@");

		my $socket = eval { Server_SSLify( $_[ARG0], sub {
			my( $socket, $status, $errval ) = @_;

			pass( "SERVER: Got callback hook" );
			is( $status, 0, "SERVER: Status received from callback is ERR - $errval" );

			$poe_kernel->post( 'myserver' => 'shutdown');
		} ) };
		ok(!$@, "SERVER: Server_SSLify $@");
		is( SSLify_GetStatus( $socket ), -1, "SERVER: SSLify_GetStatus is pending" );

		return ($socket);
	},
	ClientDisconnected	=> sub
	{
		ok(1, 'SERVER: client disconnected');
	},
	ClientInput		=> sub
	{
		my ($kernel, $heap, $line) = @_[KERNEL, HEAP, ARG0];

		die "Should have never got any input from the client!";
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
	ServerInput	=> sub
	{
		my ($kernel, $heap, $line) = @_[KERNEL, HEAP, ARG0];

		# purposefully send garbage so we screw up the ssl connect on the client-side
		$heap->{server}->put( 'garbage in, garbage out' );
	},
	ServerError	=> sub
	{
		# Thanks to H. Merijn Brand for spotting this FAIL in 5.12.0!
		# The default PoCo::Client::TCP handler will throw a warning, which causes Test::NoWarnings to FAIL :(
		my ($syscall, $errno, $error) = @_[ ARG0..ARG2 ];

		# Since this test purposefully sends garbage, we expect a connection reset by peer
		# not ok 7 - Got SERVER read error 104: Connection reset by peer

		# TODO are there other "errors" that is harmless?
		$error = "Normal disconnection" unless $error;
		my $msg = "Got CLIENT $syscall error $errno: $error";
		unless ( $syscall eq 'read' and $errno == 104 ) {
			fail( $msg );
		} else {
			diag( $msg ) if $ENV{TEST_VERBOSE};
		}
	},
);

$poe_kernel->run();

pass( 'shut down sanely' );

exit 0;
