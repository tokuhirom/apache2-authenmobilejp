use inc::Module::Install;
name 'Apache2-AuthenMobileJP';
all_from 'lib/Apache2/AuthenMobileJP.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';
use_test_base;
auto_include;
WriteAll;
