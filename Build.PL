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

	'test_files'		=> 't/*.t',

	'add_to_cleanup'	=> [ 'META.yml', 'Makefile.PL', 'README', 'Manifest' ],	# automatically generated

	'requires'		=> {
		# Networking
		'Net::SSLeay'	=>	'1.30',

		# minimum perl version
		'perl'		=> '5.006',
	},
);

# all done!
$build->create_build_script;
