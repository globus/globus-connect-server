#! /usr/bin/perl
#
# Copyright 1999-2013 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


use strict;

require 5.005;
use vars qw(@tests);
$ENV{PATH} .= ":.";

sub get_harness {
    my $xmlfile = "gcmu-test.xml";
    my $harness;

    eval "use TAP::Harness::JUnit";
    if (! $@)
    {
        $harness = TAP::Harness::JUnit->new({
                                xmlfile => $xmlfile,
                                merge => 1});
        return ($harness, 'junit');
    }
    eval "use TAP::Harness;";
    if (! $@)
    {
        my $constructor_arg = { merge => 1 };
        my $harness_type;
        eval "use TAP::Formatter::JUnit";
        if (! $@) {
            $constructor_arg->{formatter_class} = 'TAP::Formatter::JUnit';
            $harness_type = 'junit';
            open(STDOUT, ">$xmlfile");
        } else {
            $constructor_arg->{formatter_class} = 'TAP::Formatter::File';
            $constructor_arg->{verbosity} = 1;
            $harness_type = 'tap';
            open(STDOUT, ">gcmu-test.tap");
        }
        $harness = TAP::Harness->new($constructor_arg);
        return ($harness, $harness_type);
    }
    else
    {
        die "Unable to initialize test harness: $@";
    }
}

$|=1;

@tests = qw(
    command-line-options.pl
    id-setup-and-cleanup.pl
    id-setup-and-cleanup-generic.pl
    web-setup-and-cleanup.pl
    web-setup-and-cleanup-generic.pl
    io-setup-and-cleanup.pl
    io-setup-and-cleanup-generic.pl
    endpoint-options.pl
    security-options.pl
    gridftp-options.pl
    myproxy-options.pl
    oauth-options.pl
    reset-endpoint.pl
    double-server-config.pl
    activation-test.pl
    transfer-test.pl
    sharing.pl
    transfer-test-udt.pl
);

my ($harness, $harness_type) = get_harness();

if ($harness_type eq 'tap') {
    my $aggregate_test_result = 0;
    for my $testname (@tests) {
        ($harness, $_) = get_harness();
        open(STDOUT, ">$testname.tap");
        $aggregate_test_result += $harness->runtests($testname);
    }
    for my $testname (@tests) {
        system("perl tap-to-junit-xml -i $testname.tap -o $testname.xml -p $testname --puretap");
    }
    exit($aggregate_test_result);
} else {
    my $test_result = $harness->runtests(@tests);
    exit($test_result)
}
