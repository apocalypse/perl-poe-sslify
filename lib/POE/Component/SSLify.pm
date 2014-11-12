package POE::Component::SSLify;

# ABSTRACT: Makes using SSL in the world of POE easy!

BEGIN {
	# should fix netbsd smoke failures, thanks BinGOs!
	# <BinGOs> Apocal: okay cores with a 0.9.7d I've built myself from source. Doesn't if I comment out engine lines.
	# BinGOs did an awesome job building various versions of openssl to try and track down the problem, it seems like
	# newer versions of openssl worked fine on netbsd, but I don't want to do crazy stuff like probing openssl versions
	# as it's fragile - best to let the user figure it out :)
	#
	# see http://www.cpantesters.org/cpan/report/1a660280-6eb1-11e0-a462-e9956c33433b
	# http://www.cpantesters.org/cpan/report/49a9f2aa-6df2-11e0-a462-e9956c33433b
	# http://www.cpantesters.org/cpan/report/78d9a234-6df5-11e0-a462-e9956c33433b
	# and many other reports :(
	#
	#(gdb) bt
	##0  0xbd9d3e7e in engine_table_select () from /usr/lib/libcrypto.so.2
	##1  0xbd9b3bed in ENGINE_get_default_RSA () from /usr/lib/libcrypto.so.2
	##2  0xbd9b1f6d in RSA_new_method () from /usr/lib/libcrypto.so.2
	##3  0xbd9b1cf6 in RSA_new () from /usr/lib/libcrypto.so.2
	##4  0xbd9cf8a1 in RSAPrivateKey_asn1_meth () from /usr/lib/libcrypto.so.2
	##5  0xbd9da64b in ASN1_item_ex_new () from /usr/lib/libcrypto.so.2
	##6  0xbd9da567 in ASN1_item_ex_new () from /usr/lib/libcrypto.so.2
	##7  0xbd9d88cc in ASN1_item_ex_d2i () from /usr/lib/libcrypto.so.2
	##8  0xbd9d8437 in ASN1_item_d2i () from /usr/lib/libcrypto.so.2
	##9  0xbd9cf8d5 in d2i_RSAPrivateKey () from /usr/lib/libcrypto.so.2
	##10 0xbd9ad546 in d2i_PrivateKey () from /usr/lib/libcrypto.so.2
	##11 0xbd995e63 in PEM_read_bio_PrivateKey () from /usr/lib/libcrypto.so.2
	##12 0xbd980430 in PEM_read_bio_RSAPrivateKey () from /usr/lib/libcrypto.so.2
	##13 0xbda2e9dc in SSL_CTX_use_RSAPrivateKey_file () from /usr/lib/libssl.so.3
	##14 0xbda5aabe in XS_Net__SSLeay_CTX_use_RSAPrivateKey_file (cv=0x8682c80)
	#    at SSLeay.c:1716
	##15 0x08115401 in Perl_pp_entersub () at pp_hot.c:2885
	##16 0x080e0ab7 in Perl_runops_debug () at dump.c:2049
	##17 0x08078624 in S_run_body (oldscope=1) at perl.c:2308
	##18 0x08077ef2 in perl_run (my_perl=0x823f030) at perl.c:2233
	##19 0x0805e321 in main (argc=3, argv=0xbfbfe6a0, env=0xbfbfe6b0)
	#    at perlmain.c:117
	##20 0x0805e0c6 in ___start ()
	#(gdb)
	if ( ! defined &LOAD_SSL_ENGINES ) { *LOAD_SSL_ENGINES = sub () { 0 } }
}

# We need Net::SSLeay or all's a failure!
BEGIN {
	# We need >= 1.36 because it contains a lot of important fixes
	eval "use Net::SSLeay 1.36 qw( die_now die_if_ssl_error FILETYPE_PEM )";

	# Check for errors...
	if ( $@ ) {
		# Oh boy!
		die $@;
	} else {
		# Finally, load our subclasses :)
		# ClientHandle isa ServerHandle so it will get loaded automatically
		require POE::Component::SSLify::ClientHandle;

		# Initialize Net::SSLeay
		# Taken from http://search.cpan.org/~flora/Net-SSLeay-1.36/lib/Net/SSLeay.pm#Low_level_API
		Net::SSLeay::load_error_strings();
		Net::SSLeay::SSLeay_add_ssl_algorithms();
		if ( LOAD_SSL_ENGINES ) {
			Net::SSLeay::ENGINE_load_builtin_engines();
			Net::SSLeay::ENGINE_register_all_complete();
		}
		Net::SSLeay::randomize();
	}
}

# Do the exporting magic...
use parent 'Exporter';
our @EXPORT_OK = qw(
	Client_SSLify Server_SSLify
	SSLify_Options SSLify_GetCTX SSLify_GetCipher SSLify_GetSocket SSLify_GetSSL SSLify_ContextCreate SSLify_GetStatus
);

# Bring in some socket-related stuff
use Symbol qw( gensym );

# we need IO 1.24 for it's win32 fixes but it includes IO::Handle 1.27_02 which is dev...
# unfortunately we have to jump to IO 1.25 which includes IO::Handle 1.28... argh!
use IO::Handle 1.28;

# Use Scalar::Util's weaken() for the connref stuff
use Scalar::Util qw( weaken );
use Task::Weaken 1.03; # to make sure it actually works!

# load POE ( just to fool dzil AutoPrereqs :)
require POE;

# The server-side CTX stuff
my $ctx;

# global so users of this module can override it locally
our $IGNORE_SSL_ERRORS = 0;

=func Client_SSLify

This function sslifies a client-side socket. You can pass several options to it:

	my $socket = shift;
	$socket = Client_SSLify( $socket, $version, $options, $ctx, $callback );
		$socket is the non-ssl socket you got from somewhere ( required )
		$version is the SSL version you want to use
		$options is the SSL options you want to use
		$ctx is the custom SSL context you want to use
		$callback is the callback hook on success/failure of sslification

		# This is an example of the callback and you should pass it as Client_SSLify( $socket, ... , \&callback );
		sub callback {
			my( $socket, $status, $errval ) = @_;
			# $socket is the original sslified socket in case you need to play with it
			# $status is either 1 or 0; with 1 signifying success and 0 failure
			# $errval will be defined if $status == 0; it's the numeric SSL error code
			# check http://www.openssl.org/docs/ssl/SSL_get_error.html for the possible error values ( and import them from Net::SSLeay! )

			# The return value from the callback is discarded
		}

If $ctx is defined, SSLify will ignore $version and $options. Otherwise, it will be created from the $version and
$options parameters. If all of them are undefined, it will follow the defaults in L</SSLify_ContextCreate>.

BEWARE: If you passed in a CTX, SSLify will do Net::SSLeay::CTX_free( $ctx ) when the
socket is destroyed. This means you cannot reuse contexts!

NOTE: The way to have a client socket with proper certificates set up is:

	my $socket = shift;	# get the socket from somewhere
	my $ctx = SSLify_ContextCreate( 'server.key', 'server.crt' );
	$socket = Client_SSLify( $socket, undef, undef, $ctx );

NOTE: You can pass the callback anywhere in the arguments, we'll figure it out for you! If you want to call a POE event, please look
into the postback/callback stuff in L<POE::Session>.

	# we got this from POE::Wheel::SocketFactory
	sub event_SuccessEvent {
		my $socket = $_[ARG0];
		$socket = Client_SSLify( $socket, $_[SESSION]->callback( 'sslify_result' ) );
		$_[HEAP]->{client} = POE::Wheel::ReadWrite->new(
			Handle => $socket,
			...
		);
		return;
	}

	# the callback event
	sub event_sslify_result {
		my ($creation_args, $called_args) = @_[ARG0, ARG1];
		my( $socket, $status, $errval ) = @$called_args;

		if ( $status ) {
			print "Yay, SSLification worked!";
		} else {
			print "Aw, SSLification failed with error $errval";
		}
	}
=cut

sub Client_SSLify {
	# Get the socket + version + options + ctx + callback
	my( $socket, $version, $options, $custom_ctx, $callback ) = @_;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# Mangle the callback stuff
	if ( defined $version and ref $version and ref( $version ) eq 'CODE' ) {
		$callback = $version;
		$version = $options = $custom_ctx = undef;
	} elsif ( defined $options and ref $options and ref( $options ) eq 'CODE' ) {
		$callback = $options;
		$options = $custom_ctx = undef;
	} elsif ( defined $custom_ctx and ref $custom_ctx and ref( $custom_ctx ) eq 'CODE' ) {
		$callback = $custom_ctx;
		$custom_ctx = undef;
	}

	# From IO::Handle POD
	# If an error occurs blocking will return undef and $! will be set.
	if ( ! defined $socket->blocking( 0 ) ) {
		die "Unable to set nonblocking mode on socket: $!";
	}

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ClientHandle', $socket, $version, $options, $custom_ctx, $callback ) or die "Unable to tie to our subclass: $!";

	# argh, store the newsock in the tied class to use for callback
	if ( defined $callback ) {
		tied( *$newsock )->{'orig_socket'} = $newsock;
		weaken( tied( *$newsock )->{'orig_socket'} );
	}

	# All done!
	return $newsock;
}

=func Server_SSLify

This function sslifies a server-side socket. You can pass several options to it:

	my $socket = shift;
	$socket = Server_SSLify( $socket, $ctx, $callback );
		$socket is the non-ssl socket you got from somewhere ( required )
		$ctx is the custom SSL context you want to use; overrides the global ctx set in SSLify_Options
		$callback is the callback hook on success/failure of sslification

BEWARE: L</SSLify_Options> must be called first if you aren't passing a $ctx. If you want to set some options per-connection, do this:

	my $socket = shift;	# get the socket from somewhere
	my $ctx = SSLify_ContextCreate();
	# set various options on $ctx as desired
	$socket = Server_SSLify( $socket, $ctx );

NOTE: You can use L</SSLify_GetCTX> to modify the global, and avoid doing this on every connection if the
options are the same...

Please look at L</Client_SSLify> for more details on the callback hook.
=cut

sub Server_SSLify {
	# Get the socket!
	my( $socket, $custom_ctx, $callback ) = @_;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# If we don't have a ctx ready, we can't do anything...
	if ( ! defined $ctx and ! defined $custom_ctx ) {
		die 'Please do SSLify_Options() first ( or pass in a $ctx object )';
	}

	# mangle custom_ctx depending on callback
	if ( defined $custom_ctx and ref $custom_ctx and ref( $custom_ctx ) eq 'CODE' ) {
		$callback = $custom_ctx;
		$custom_ctx = undef;
	}

	# From IO::Handle POD
	# If an error occurs blocking will return undef and $! will be set.
	if ( ! defined $socket->blocking( 0 ) ) {
		die "Unable to set nonblocking mode on socket: $!";
	}

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ServerHandle', $socket, ( $custom_ctx || $ctx ), $callback ) or die "Unable to tie to our subclass: $!";

	# argh, store the newsock in the tied class to use for connref
	if ( defined $callback ) {
		tied( *$newsock )->{'orig_socket'} = $newsock;
		weaken( tied( *$newsock )->{'orig_socket'} );
	}

	# All done!
	return $newsock;
}

=func SSLify_ContextCreate

Accepts some options, and returns a brand-new Net::SSLeay context object ( $ctx )

	my $ctx = SSLify_ContextCreate( $key, $cert, $version, $options );
		$key is the certificate key file
		$cert is the certificate file
		$version is the SSL version to use
		$options is the SSL options to use

You can then call various Net::SSLeay methods on the context

	my $mode = Net::SSLeay::CTX_get_mode( $ctx );

By default we don't use the SSL key + certificate files

By default we use the version: default. Known versions of the SSL connection - look at
L<http://www.openssl.org/docs/ssl/SSL_CTX_new.html> for more info.

	* sslv2
	* sslv3
	* tlsv1
	* sslv23
	* default ( sslv23 )

By default we don't set any options - look at L<http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html> for more info.
=cut

sub SSLify_ContextCreate {
	# Get the key + cert + version + options
	my( $key, $cert, $version, $options ) = @_;

	return _createSSLcontext( $key, $cert, $version, $options );
}

=func SSLify_Options

Call this function to initialize the global server-side context object. This will be the default context whenever you call
L</Server_SSLify> without passing a custom context to it.

	SSLify_Options( $key, $cert, $version, $options );
		$key is the certificate key file ( required )
		$cert is the certificate file ( required )
		$version is the SSL version to use
		$options is the SSL options to use

By default we use the version: default

By default we use the options: Net::SSLeay::OP_ALL

Please look at L</SSLify_ContextCreate> for more info on the available versions/options.
=cut

sub SSLify_Options {
	# Get the key + cert + version + options
	my( $key, $cert, $version, $options ) = @_;

	# sanity
	if ( ! defined $key or ! defined $cert ) {
		die 'no key/cert specified';
	}

	# Set the default
	if ( ! defined $options ) {
		$options = Net::SSLeay::OP_ALL();
	}

	# set the context, possibly overwriting the previous one
	if ( defined $ctx ) {
		Net::SSLeay::CTX_free( $ctx );
		undef $ctx;
	}
	$ctx = _createSSLcontext( $key, $cert, $version, $options );

	# all done!
	return 1;
}

sub _createSSLcontext {
	my( $key, $cert, $version, $options ) = @_;

	my $context;
	if ( defined $version and ! ref $version ) {
		if ( $version eq 'sslv2' ) {
			$context = Net::SSLeay::CTX_v2_new();
		} elsif ( $version eq 'sslv3' ) {
			$context = Net::SSLeay::CTX_v3_new();
		} elsif ( $version eq 'tlsv1' ) {
			$context = Net::SSLeay::CTX_tlsv1_new();
		} elsif ( $version eq 'sslv23' ) {
			$context = Net::SSLeay::CTX_v23_new();
		} elsif ( $version eq 'default' ) {
			$context = Net::SSLeay::CTX_new();
		} else {
			die "unknown SSL version: $version";
		}
	} else {
		$context = Net::SSLeay::CTX_new();
	}
	if ( ! defined $context ) {
		die_now( "Failed to create SSL_CTX $!" );
		return;
	}

	# do we need to set options?
	if ( defined $options ) {
		Net::SSLeay::CTX_set_options( $context, $options );
		die_if_ssl_error( 'ssl ctx set options' ) if ! $IGNORE_SSL_ERRORS;
	}

	# do we need to set key/etc?
	if ( defined $key ) {
		# Following will ask password unless private key is not encrypted
		Net::SSLeay::CTX_use_RSAPrivateKey_file( $context, $key, FILETYPE_PEM );
		die_if_ssl_error( 'private key' ) if ! $IGNORE_SSL_ERRORS;
	}

	# Set the cert file
	if ( defined $cert ) {
		Net::SSLeay::CTX_use_certificate_chain_file( $context, $cert );
		die_if_ssl_error( 'certificate' ) if ! $IGNORE_SSL_ERRORS;
	}

	# All done!
	return $context;
}

=func SSLify_GetCTX

Returns the actual Net::SSLeay context object in case you wanted to play with it :)

If passed in a socket, it will return that socket's $ctx instead of the global.

	my $ctx = SSLify_GetCTX();			# get the one set via SSLify_Options
	my $ctx = SSLify_GetCTX( $sslified_sock );	# get the one in the object
=cut

sub SSLify_GetCTX {
	my $sock = shift;
	if ( ! defined $sock ) {
		return $ctx;
	} else {
		return tied( *$sock )->{'ctx'};
	}
}

=func SSLify_GetCipher

Returns the cipher used by the SSLified socket

	print "SSL Cipher is: " . SSLify_GetCipher( $sslified_sock ) . "\n";

NOTE: Doing this immediately after Client_SSLify or Server_SSLify will result in "(NONE)" because the SSL handshake
is not done yet. The socket is nonblocking, so you will have to wait a little bit for it to get ready.

	apoc@blackhole:~/mygit/perl-poe-sslify/examples$ perl serverclient.pl
	got connection from: 127.0.0.1 - commencing Server_SSLify()
	SSLified: 127.0.0.1 cipher type: ((NONE))
	Connected to server, commencing Client_SSLify()
	SSLified the connection to the server
	Connected to SSL server
	Input: hola
	got input from: 127.0.0.1 cipher type: (AES256-SHA) input: 'hola'
	Got Reply: hola
	Input: ^C
	stopped at serverclient.pl line 126.
=cut

sub SSLify_GetCipher {
	my $sock = shift;
	return Net::SSLeay::get_cipher( tied( *$sock )->{'ssl'} );
}

=func SSLify_GetSocket

Returns the actual socket used by the SSLified socket, useful for stuff like getpeername()/getsockname()

	print "Remote IP is: " . inet_ntoa( ( unpack_sockaddr_in( getpeername( SSLify_GetSocket( $sslified_sock ) ) ) )[1] ) . "\n";
=cut

sub SSLify_GetSocket {
	my $sock = shift;
	return tied( *$sock )->{'socket'};
}

=func SSLify_GetSSL

Returns the actual Net::SSLeay object so you can call methods on it

	print Net::SSLeay::dump_peer_certificate( SSLify_GetSSL( $sslified_sock ) );
=cut

sub SSLify_GetSSL {
	my $sock = shift;
	return tied( *$sock )->{'ssl'};
}

=func SSLify_GetStatus

Returns the status of the SSL negotiation/handshake/connection. See L<http://www.openssl.org/docs/ssl/SSL_connect.html#RETURN_VALUES>
for more info.

	my $status = SSLify_GetStatus( $socket );
		-1 = still in negotiation stage ( or error )
		 0 = internal SSL error, connection will be dead
		 1 = negotiation successful
=cut

sub SSLify_GetStatus {
	my $sock = shift;
	return tied( *$sock )->{'status'};
}

1;

=pod

=head1 SYNOPSIS

	# look at the DESCRIPTION for client and server example code

=head1 DESCRIPTION

This component is a method to simplify the SSLification of a socket before it is passed
to a L<POE::Wheel::ReadWrite> wheel in your application.

=head2 Client usage

	# Import the module
	use POE::Component::SSLify qw( Client_SSLify );

	# Create a normal SocketFactory wheel and connect to a SSL-enabled server
	my $factory = POE::Wheel::SocketFactory->new;

	# Time passes, SocketFactory gives you a socket when it connects in SuccessEvent
	# Convert the socket into a SSL socket POE can communicate with
	my $socket = shift;
	eval { $socket = Client_SSLify( $socket ) };
	if ( $@ ) {
		# Unable to SSLify it...
	}

	# Now, hand it off to ReadWrite
	my $rw = POE::Wheel::ReadWrite->new(
		Handle	=>	$socket,
		# other options as usual
	);

=head2 Server usage

	# !!! Make sure you have a public key + certificate
	# excellent howto: http://www.akadia.com/services/ssh_test_certificate.html

	# Import the module
	use POE::Component::SSLify qw( Server_SSLify SSLify_Options );

	# Set the key + certificate file
	eval { SSLify_Options( 'server.key', 'server.crt' ) };
	if ( $@ ) {
		# Unable to load key or certificate file...
	}

	# Create a normal SocketFactory wheel to listen for connections
	my $factory = POE::Wheel::SocketFactory->new;

	# Time passes, SocketFactory gives you a socket when it gets a connection in SuccessEvent
	# Convert the socket into a SSL socket POE can communicate with
	my $socket = shift;
	eval { $socket = Server_SSLify( $socket ) };
	if ( $@ ) {
		# Unable to SSLify it...
	}

	# Now, hand it off to ReadWrite
	my $rw = POE::Wheel::ReadWrite->new(
		Handle	=>	$socket,
		# other options as usual
	);

=head1 NOTES

=head2 Socket methods doesn't work

The new socket this module gives you actually is tied socket magic, so you cannot do stuff like
getpeername() or getsockname(). The only way to do it is to use L</SSLify_GetSocket> and then operate on
the socket it returns.

=head2 Dying everywhere...

This module will die() if Net::SSLeay could not be loaded or it is not the version we want. So, it is recommended
that you check for errors and not use SSL, like so:

	eval { use POE::Component::SSLify };
	if ( $@ ) {
		$sslavailable = 0;
	} else {
		$sslavailable = 1;
	}

	# Make socket SSL!
	if ( $sslavailable ) {
		eval { $socket = POE::Component::SSLify::Client_SSLify( $socket ) };
		if ( $@ ) {
			# Unable to SSLify the socket...
		}
	}

=head3 $IGNORE_SSL_ERRORS

As of SSLify v1.003 you can override this variable to temporarily ignore some SSL errors. This is useful if you are doing crazy things
with the underlying Net::SSLeay stuff and don't want to die. However, it won't ignore all errors as some is still considered fatal.
Here's an example:

	{
		local $POE::Component::SSLify::IGNORE_SSL_ERRORS=1;
		my $ctx = SSLify_CreateContext(...);
		#Some more stuff
	}

=head2 OpenSSL functions

Theoretically you can do anything that Net::SSLeay exports from the OpenSSL libs on the socket. However, I have not tested every
possible function against SSLify, so use them carefully!

=head3 Net::SSLeay::renegotiate

This function has been tested ( it's in C<t/2_renegotiate_client.t> ) but it doesn't work on FreeBSD! I tracked it down to this security
advisory: L<http://security.freebsd.org/advisories/FreeBSD-SA-09:15.ssl.asc> which explains it in detail. The test will skip this function
if it detects that you're on a broken system. However, if you have the updated OpenSSL library that fixes this you can use it.

NOTE: Calling this means the callback function you passed in L</Client_SSLify> or L</Server_SSLify> will not fire! If you need this
please let me know and we can come up with a way to make it work.

=head2 Upgrading a non-ssl socket to SSL

You can have a normal plaintext socket, and convert it to SSL anytime. Just keep in mind that the client and the server must agree to sslify
at the same time, or they will be waiting on each other forever! See C<t/3_upgrade.t> for an example of how this works.

=head2 Downgrading a SSL socket to non-ssl

As of now this is unsupported. If you need this feature please let us know and we'll work on it together!

=head2 MSWin32 is not supported

This module doesn't work on MSWin32 platforms at all ( XP, Vista, 7, etc ) because of some weird underlying fd issues. Since I'm not a windows
developer, I'm unable to fix this. However, it seems like Cygwin on MSWin32 works just fine! Please help me fix this if you can, thanks!

=head2 LOAD_SSL_ENGINES

OpenSSL supports loading ENGINEs to accelerate the crypto algorithms. SSLify v1.004 automatically loaded the engines, but there was some
problems on certain platforms that caused coredumps. A big shout-out to BinGOs and CPANTesters for catching this! It's now disabled in v1.007
and you would need to explicitly enable it.

	sub POE::Component::SSLify::LOAD_SSL_ENGINES () { 1 }
	use POE::Component::SSLify qw( Client::SSLify );

=head1 EXPORT

Stuffs all of the functions in @EXPORT_OK so you have to request them directly.

=head1 SEE ALSO
POE
Net::SSLeay

=head1 ACKNOWLEDGEMENTS

	Original code is entirely Rocco Caputo ( Creator of POE ) -> I simply
	packaged up the code into something everyone could use and accepted the burden
	of maintaining it :)

	From the PoCo::Client::HTTP code =]
	# This code should probably become a POE::Kernel method,
	# seeing as it's rather baroque and potentially useful in a number
	# of places.

ASCENT also helped a lot with the nonblocking mode, without his hard work this
module would still be stuck in the stone age :)

A lot of people helped add various features/functions - please look at the changelog for more detail.

=cut
