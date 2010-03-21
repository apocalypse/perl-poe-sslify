# Build.PL
use strict; use warnings;
use Module::Build;

my $build = Module::Build->new(
	# look up Module::Build::API for the info!
	'dynamic_config'	=> 0,
	'module_name'		=> 'POE::Component::SSLify',
	'license'		=> 'perl',

	'dist_abstract'		=> 'SSL in the world of POE made easy',

	'create_packlist'	=> 1,
	'create_makefile_pl'	=> 'traditional',
	'create_readme'		=> 1,
	'create_license'	=> 1,
	'sign'			=> 0,

	'test_files'		=> 't/*.t',

	'add_to_cleanup'	=> [ 'META.yml', 'Makefile.PL', 'README', 'Manifest', 'LICENSE' ],	# automatically generated

	'requires'		=> {
		# Networking
		'Net::SSLeay'	=>	'1.36',

		# minimum perl version
		'perl'		=> '5.006',
	},

	'build_requires'	=> {
		# For the t/simple.t test
		'POE'				=> 0,
		'POE::Component::Client::TCP'	=> 0,
		'POE::Component::Server::TCP'	=> 0,
	},

	# include the standard stuff in META.yml
	'meta_merge'	=> {
		'resources'	=> {
			'license'	=> 'http://dev.perl.org/licenses/',
			'homepage'	=> 'http://search.cpan.org/dist/POE-Component-SSLify',
			'bugtracker'	=> 'http://rt.cpan.org/NoAuth/Bugs.html?Dist=POE-Component-SSLify',
			'repository'	=> 'http://github.com/apocalypse/perl-poe-sslify',
		},
	},
);

# all done!
$build->create_build_script;
