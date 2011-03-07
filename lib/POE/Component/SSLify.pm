package POE::Component::SSLify;

# ABSTRACT: Makes using SSL in the world of POE easy!

# We need Net::SSLeay or all's a failure!
BEGIN {
	# We need >= 1.36 because it contains a lot of important fixes
	eval "use Net::SSLeay 1.36 qw( die_now die_if_ssl_error )";

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
		# TODO do we need this?
		#Net::SSLeay::ENGINE_load_builtin_engines();  # If you want built-in engines
	        #Net::SSLeay::ENGINE_register_all_complete(); # If you want built-in engines
		Net::SSLeay::randomize();
	}
}

# Do the exporting magic...
require Exporter;
our @ISA = qw( Exporter );
our @EXPORT_OK = qw( Client_SSLify Server_SSLify SSLify_Options SSLify_GetCTX SSLify_GetCipher SSLify_GetSocket SSLify_GetSSL SSLify_ContextCreate );

# Bring in some socket-related stuff
use Symbol qw( gensym );

# we need IO 1.24 for it's win32 fixes but it includes IO::Handle 1.27_02 which is dev...
# unfortunately we have to jump to IO 1.25 which includes IO::Handle 1.28... argh!
use IO::Handle 1.28;

# The server-side CTX stuff
my $ctx = undef;

# global so users of this module can override it locally
our $IGNORE_SSL_ERRORS = 0;

=func Client_SSLify

Accepts a socket, returns a brand new socket SSLified. Optionally accepts SSL
context data. Also accepts a subref to call when connection/negotiation is done.

	my $socket = shift;						# get the socket from somewhere
	$socket = Client_SSLify( $socket );				# the default
	$socket = Client_SSLify( $socket, $version, $options );		# sets more options for the context
	$socket = Client_SSLify( $socket, undef, undef, $ctx );		# pass in a custom context
	$socket = Client_SSLify( $socket, sub { print "CONNECTED" } );	# call your connection function

If $ctx is defined, SSLify will ignore other args. If $ctx isn't defined, SSLify
will create it from the $version + $options parameters.

Known versions:
	* sslv2
	* sslv3
	* tlsv1
	* default

By default we use the version: default

By default we don't set any options

NOTE: The way to have a client socket with proper certificates set up is:

	my $socket = shift;	# get the socket from somewhere
	my $ctx = SSLify_ContextCreate( 'server.key', 'server.crt' );
	$socket = Client_SSLify( $socket, undef, undef, $ctx );

BEWARE: If you passed in a CTX, SSLify will do Net::SSLeay::CTX_free( $ctx ) when the
socket is destroyed. This means you cannot reuse contexts!

NOTE: You can pass the subref anywhere in the arguments, we'll figure it out for you! If you want to call a POE event, please look
into the postback/callback stuff in POE::Session. The subref will get the socket as the sole argument.

	$socket = Client_SSLify( $socket, $session->callback( 'got_connect' => @args ) );
=cut

sub Client_SSLify {
	# Get the socket + version + options + ctx
	my( $socket, $version, $options, $ctx, $connref ) = @_;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# Mangle the connref stuff
	if ( defined $version and ref $version and ref( $version ) eq 'CODE' ) {
		$connref = $version;
		$version = $options = $ctx = undef;
	} elsif ( defined $options and ref $options and ref( $options ) eq 'CODE' ) {
		$connref = $options;
		$options = $ctx = undef;
	} elsif ( defined $ctx and ref $ctx and ref( $ctx ) eq 'CODE' ) {
		$connref = $ctx;
		$ctx = undef;
	}

	# From IO::Handle POD
	# If an error occurs blocking will return undef and $! will be set.
	if ( ! defined $socket->blocking( 0 ) ) {
		die "Unable to set nonblocking mode on socket: $!";
	}

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ClientHandle', $socket, $version, $options, $ctx, $connref ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}

=func Server_SSLify

Accepts a socket, returns a brand new socket SSLified. Also accepts a custom context. Also accepts a subref
to call when connection/negotiation is done.

	my $socket = shift;	# get the socket from somewhere
	$socket = Server_SSLify( $socket );
	$socket = Server_SSLify( $socket, $ctx );			# use your custom context
	$socket = Server_SSLify( $socket, sub { print "CONNECTED" } );	# call your connection function

NOTE: SSLify_Options must be set first!

Furthermore, you can pass in your own $ctx object if you desire. This allows you to set custom parameters
per-connection, for example.

	my $socket = shift;	# get the socket from somewhere
	my $ctx = SSLify_ContextCreate();
	# set various options on $ctx as desired
	$socket = Server_SSLify( $socket, $ctx );

NOTE: You can use SSLify_GetCTX to modify the global, and avoid doing this on every connection if the
options are the same...

NOTE: You can pass the subref anywhere in the arguments, we'll figure it out for you! If you want to call a POE event, please look
into the postback/callback stuff in POE::Session. The subref will get the socket as the sole argument.

	$socket = Server_SSLify( $socket, $session->callback( 'got_connect' => @args ) );
=cut

sub Server_SSLify {
	# Get the socket!
	my( $socket, $custom_ctx, $connref ) = @_;

	# Validation...
	if ( ! defined $socket ) {
		die "Did not get a defined socket";
	}

	# If we don't have a ctx ready, we can't do anything...
	if ( ! defined $ctx and ! defined $custom_ctx ) {
		die 'Please do SSLify_Options() first ( or pass in a $ctx object )';
	}

	# mangle custom_ctx depending on connref
	if ( defined $custom_ctx and ref $custom_ctx and ref( $custom_ctx ) eq 'CODE' ) {
		$connref = $custom_ctx;
		$custom_ctx = undef;
	}

	# From IO::Handle POD
	# If an error occurs blocking will return undef and $! will be set.
	if ( ! defined $socket->blocking( 0 ) ) {
		die "Unable to set nonblocking mode on socket: $!";
	}

	# Now, we create the new socket and bind it to our subclass of Net::SSLeay::Handle
	my $newsock = gensym();
	tie( *$newsock, 'POE::Component::SSLify::ServerHandle', $socket, ( $custom_ctx || $ctx ), $connref ) or die "Unable to tie to our subclass: $!";

	# All done!
	return $newsock;
}

=func SSLify_ContextCreate

	Accepts some options, and returns a brand-new Net::SSLeay context object ( $ctx )
		my $ctx = SSLify_ContextCreate( $key, $cert, $version, $options );

	You can then call various Net::SSLeay methods on the context
		my $mode = Net::SSLeay::CTX_get_mode( $ctx );

	By default we don't use the SSL key + certificate files

	By default we use the version: default

		Known versions:
		* sslv2
		* sslv3
		* tlsv1
		* default

	By default we don't set any options
=cut

sub SSLify_ContextCreate {
	# Get the key + cert + version + options
	my( $key, $cert, $version, $options ) = @_;

	return _createSSLcontext( $key, $cert, $version, $options );
}

=func SSLify_Options

	Call this function to initialize the global server-side CTX. Accepts the location of the
	SSL key + certificate files, which is required.

	Optionally accepts the SSL version + CTX options
		SSLify_Options( $key, $cert, $version, $options );

	By default we use the version: default

		Known versions:
		* sslv2
		* sslv3
		* tlsv1
		* default

	By default we use the options: &Net::SSLeay::OP_ALL
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
		$options = &Net::SSLeay::OP_ALL;
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
		Net::SSLeay::CTX_use_RSAPrivateKey_file( $context, $key, &Net::SSLeay::FILETYPE_PEM );
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

	Example:
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

	Example:
		print "Remote IP is: " . inet_ntoa( ( unpack_sockaddr_in( getpeername( SSLify_GetSocket( $sslified_sock ) ) ) )[1] ) . "\n";
=cut

sub SSLify_GetSocket {
	my $sock = shift;
	return tied( *$sock )->{'socket'};
}

=func SSLify_GetSSL

	Returns the actual Net::SSLeay object so you can call methods on it

	Example:
		print Net::SSLeay::dump_peer_certificate( SSLify_GetSSL( $sslified_sock ) );
=cut

sub SSLify_GetSSL {
	my $sock = shift;
	return tied( *$sock )->{'ssl'};
}

1;

=pod

=head1 SYNOPSIS

	# CLIENT-side usage

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

	# --------------------------------------------------------------------------- #

	# SERVER-side usage

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

=head1 DESCRIPTION

This component represents the standard way to do SSL in POE.

=head1 NOTES

=head2 Socket methods doesn't work

The new socket this module gives you actually is some tied socket magic, so you cannot do stuff like
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

This function has been tested ( it's in C<t/2_renegotiate.t> ) but it doesn't work on FreeBSD! I tracked it down to this security advisory:
L<http://security.freebsd.org/advisories/FreeBSD-SA-09:15.ssl.asc> which explains it in detail. The test will skip this function
if it detects that you're on a broken system. However, if you have the updated OpenSSL library that fixes this you can use it.

=head2 In-Situ sslification

You can have a normal plaintext socket, and convert it to SSL anytime. Just keep in mind that the client and the server must agree to sslify
at the same time, or they will be waiting on each other forever! See C<t/3_insitu.t> for an example of how this works.

=head2 MSWin32 is not supported

This module doesn't work on MSWin32 platforms at all ( XP, Vista, 7, etc ) because of some weird underlying fd issues. Since I'm not a windows
developer, I'm unable to fix this. However, it seems like Cygwin on MSWin32 works just fine! Please help me fix this if you can, thanks!

=head1 EXPORT

	Stuffs all of the above functions in @EXPORT_OK so you have to request them directly

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

=cut
