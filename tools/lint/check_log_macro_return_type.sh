#!/usr/bin/env bash
# check_log_macro_return_type.sh
#
# The LOG_* guard macros return from the enclosing function. This gate catches
# the return-value/type mismatches that compile but invert behavior, such as
# LOG_ERR (return -1) inside a bool-returning function.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

perl - <<'PERL' "$@"
use strict;
use warnings;
use File::Find;

my @roots = @ARGV ? @ARGV : qw(app lib config tools);
my @files;

find(
    sub {
        return unless -f $_;
        return unless /\.(?:c|h)\z/;
        my $path = $File::Find::name;
        return if $path =~ m{(?:^|/)(?:build|vendor|\.git)(?:/|\z)};
        return if $path =~ m{^(?:\./)?lib/test/};
        return if $path eq './lib/util/include/util/log_macros.h';
        # wf/dx-scanner-immunity: under a production scan (ZCL_LINT_PRODUCTION_SCAN=1,
        # set by the Makefile's check-% pattern — see tools/lint/scan_exclusions.sh)
        # skip the shared transient-fixture-name glob so a sibling gate's selftest
        # fixture can never trip this gate mid-race. Direct selftest invocation
        # (no ZCL_LINT_PRODUCTION_SCAN) keeps full detection power.
        return if ($ENV{ZCL_LINT_PRODUCTION_SCAN} // '') eq '1'
            && $path =~ m{(?:^|/)_[^/]*fixture[^/]*\.[ch]\z};
        push @files, $path;
    },
    @roots
);

sub scrub_line {
    my ($line, $in_block_ref) = @_;
    chomp $line;
    my $out = '';
    while (length $line) {
        if ($$in_block_ref) {
            if ($line =~ s/^.*?\*\///) {
                $$in_block_ref = 0;
                next;
            }
            return $out;
        }
        if ($line =~ s/^(.*?)\/\*.*?\*\///) {
            $out .= $1;
            next;
        }
        if ($line =~ s/^(.*?)\/\*.*\z//) {
            $out .= $1;
            $$in_block_ref = 1;
            last;
        }
        $out .= $line;
        last;
    }
    $out =~ s{//.*\z}{};
    $out =~ s/"(?:\\.|[^"\\])*"/""/g;
    $out =~ s/'(?:\\.|[^'\\])*'/''/g;
    return $out;
}

sub brace_delta {
    my ($code) = @_;
    my $opens = ($code =~ tr/{//);
    my $closes = ($code =~ tr/}//);
    return $opens - $closes;
}

sub function_from_signature {
    my ($sig) = @_;
    $sig =~ s/\s+/ /g;
    $sig =~ s/^\s+|\s+\z//g;
    return unless length $sig;
    return if $sig =~ /\A#/;
    return if $sig =~ /\A(?:if|for|while|switch|else|do|struct|enum|union|typedef)\b/;
    return if $sig =~ /[=;]/;
    $sig =~ s/\s+__attribute__\s*\(\(.*\)\)\s*\z//;
    return unless $sig =~ /\A(.+)\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\z/;
    my ($ret, $name) = ($1, $2);
    $ret =~ s/\s+\z//;
    return unless length $ret;
    return ($ret, $name);
}

sub return_type_is_bool {
    my ($ret) = @_;
    $ret =~ s/\b(?:static|inline|extern|const|volatile|register)\b/ /g;
    $ret =~ s/\s+/ /g;
    return $ret =~ /(?:\A|[^A-Za-z0-9_])(?:bool|_Bool)(?:\z|[^A-Za-z0-9_])/;
}

my @bad;

for my $file (sort @files) {
    open my $fh, '<', $file or die "open $file: $!";
    my @lines = <$fh>;
    close $fh;

    my $depth = 0;
    my $decl = '';
    my $in_block_comment = 0;
    my ($func_name, $ret_type, $ret_is_bool) = ('', '', 0);

    for (my $i = 0; $i < @lines; $i++) {
        my $line_no = $i + 1;
        my $raw = $lines[$i];
        my $code = scrub_line($raw, \$in_block_comment);

        if ($depth == 0) {
            if ($code =~ /^\s*#/) {
                $decl = '';
            }
            if ($code =~ /^\s*[A-Z][A-Z0-9_]+\s*\([^;{}]*\)\s*$/) {
                $decl = '';
                next;
            }
            $decl .= $code;
            if ($code =~ /\{/) {
                my $candidate = $decl;
                $candidate =~ s/\{.*\z//s;
                my @fn = function_from_signature($candidate);
                if (@fn) {
                    ($ret_type, $func_name) = @fn;
                    $ret_is_bool = return_type_is_bool($ret_type);
                } else {
                    ($func_name, $ret_type, $ret_is_bool) = ('', '', 0);
                }
                $decl = '';
            } elsif ($code =~ /;/) {
                $decl = '';
            }
        }

        if ($func_name ne '') {
            if ($ret_is_bool && $raw =~ /\b(LOG_ERR|LOG_NULL)\s*\(/) {
                push @bad, sprintf(
                    "%s:%d: %s returns %s but %s returns %s",
                    $file, $line_no, $func_name, $ret_type, $1,
                    $1 eq 'LOG_ERR' ? '-1' : 'NULL'
                );
            }
            if (!$ret_is_bool && $raw =~ /\bLOG_FAIL\s*\(/) {
                push @bad, sprintf(
                    "%s:%d: %s returns %s but LOG_FAIL returns false",
                    $file, $line_no, $func_name, $ret_type
                );
            }
        }

        $depth += brace_delta($code);
        if ($depth <= 0) {
            $depth = 0;
            ($func_name, $ret_type, $ret_is_bool) = ('', '', 0);
            $decl = '' if $code =~ /\}/;
        }
    }
}

if (@bad) {
    print "FAIL: LOG_* macro return-type mismatches found:\n";
    print "  $_\n" for @bad;
    print "Use LOG_FAIL only in bool-returning functions, LOG_ERR only in int-returning handlers/functions, and LOG_NULL only in pointer-returning functions.\n";
    exit 1;
}

print "check_log_macro_return_type: clean\n";
exit 0;
PERL
