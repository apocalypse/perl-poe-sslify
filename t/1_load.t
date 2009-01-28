#!/usr/bin/perl

# Import the stuff
# XXX no idea why this is broken for this particular dist!
#use Test::UseAllModules;
#BEGIN { all_uses_ok(); }

use Test::More tests => 4;
use_ok( 'POE::Component::Fuse' );
use_ok( 'POE::Component::Fuse::SubProcess' );
use_ok( 'POE::Component::Fuse::AsyncFsV' );
use_ok( 'POE::Component::Fuse::myFuse' );
