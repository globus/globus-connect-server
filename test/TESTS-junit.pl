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
use Config;

require 5.005;
use vars qw(@tests);
$ENV{PATH} .= ":.";

sub get_harness_type {

    eval "use TAP::Harness::JUnit";
    if (! $@)
    {
        return 'junit';
    }
    eval "use TAP::Harness;";
    if (! $@)
    {
        eval "use TAP::Formatter::JUnit";
        if (! $@) {
            return 'junit';
        } else {
            return 'tap';
        }
    }
    else
    {
        die "Unable to initialize test harness: $@";
    }
}
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
        }
        $harness = TAP::Harness->new($constructor_arg);
        return ($harness, $harness_type);
    }
    die "Unable to initialize test harness: $@";
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
    transfer-test-udt.pl
);
# sharing.pl

my ($harness_type) = get_harness_type();

if ($harness_type eq 'tap') {
    my $aggregate_test_result = 0;
    for my $testname (@tests) {
        my $output;
        system("$Config{perlpath} $testname > $testname.tap 2>&1");
        my $aggregate_test_result += $?;
    }

    for my $testname (@tests) {
        system("perl tap-to-junit-xml -i $testname.tap -o $testname.xml -p $testname --puretap");
    }
    exit($aggregate_test_result);
} else {
    my $harness;
    ($harness, $_) = get_harness();
    my $test_result = $harness->runtests(@tests);
    exit($test_result)
}
