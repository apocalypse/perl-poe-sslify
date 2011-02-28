package POE::Component::SSLify::ClientHandle;

# ABSTRACT: Client-side handle for SSLify

# Import the SSL death routines
use Net::SSLeay 1.36 qw( die_now die_if_ssl_error );

# We inherit from ServerHandle
require POE::Component::SSLify::ServerHandle;
our @ISA = qw( POE::Component::SSLify::ServerHandle );

# Override TIEHANDLE because we create a CTX
sub TIEHANDLE {
	my ( $class, $socket, $version, $options, $ctx ) = @_;

	# create a context, if necessary
	if ( ! defined $ctx ) {
		$ctx = POE::Component::SSLify::_createSSLcontext( undef, undef, $version, $options );
	}

	my $ssl = Net::SSLeay::new( $ctx ) or die_now( "Failed to create SSL $!" );

	my $fileno = fileno( $socket );

	Net::SSLeay::set_fd( $ssl, $fileno );   # Must use fileno

	# Socket is in non-blocking mode, so connect() will return immediately.
	# die_if_ssl_error won't die on non-blocking errors. We don't need to call connect()
	# again, because OpenSSL I/O functions (read, write, ...) can handle that entirely
	# by self (it's needed to connect() once to determine connection type).
	my $resp = Net::SSLeay::connect( $ssl ) or die_if_ssl_error( 'ssl connect' );

	my $self = bless {
		'ssl'		=> $ssl,
		'ctx'		=> $ctx,
		'socket'	=> $socket,
		'fileno'	=> $fileno,
		'client'	=> 1,
	}, $class;

	return $self;
}

1;

=pod

=head1 DESCRIPTION

	This is a subclass of ServerHandle to accomodate clients setting custom context objects.

=head1 SEE ALSO
POE::Component::SSLify::ServerHandle

=cut
