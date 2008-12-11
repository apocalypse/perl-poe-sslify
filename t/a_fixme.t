#!/usr/bin/perl

use Test::More;

# AUTHOR test
if ( not $ENV{TEST_AUTHOR} ) {
	plan skip_all => 'Author test. Sent $ENV{TEST_AUTHOR} to a true value to run.';
} else {
	eval "use Test::Fixme";
	if ( $@ ) {
		plan skip_all => 'Test::Fixme required for checking for presence of to-do stuff!';
	} else {
		run_tests(
			'where'		=> [ 'lib', 't' ],
			'match'		=> 'FIX' . 'ME',	# weird work-around suggested in POD so we don't catch ourself!
		);
	}
}
