#!/usr/bin/perl

use Test::More;

# Import the stuff
eval "use Test::UseAllModules";
if ( $@ ) {
	plan skip_all => 'Test::UseAllModules required for verifying perl modules';
} else {
	all_uses_ok();
}
