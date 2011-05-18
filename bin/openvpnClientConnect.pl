#!/usr/bin/perl

#
# Copyright (c) 2008, Brane F. Gracnar
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# + Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer.
#
# + Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#
# + Neither the name of the Brane F. Gracnar nor the names of its contributors
#   may be used to endorse or promote products derived from this software without
#   specific prior written permission.
#
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# $Id$
# $LastChangedRevision$
# $LastChangedBy$
# $LastChangedDate$


use strict;
use warnings;

use Socket;
use FindBin;
use IO::File;
use Net::LDAP;
use IO::Handle;
use File::Spec;
use File::Copy;
use Sys::Syslog;
use Getopt::Long;
use File::Basename;
use Cwd qw(realpath);
use POSIX qw(strftime);
use List::Util qw(shuffle);

#############################################################
#                    RUNTIME VARIABLES                      #
#############################################################

my $MYNAME = basename($0);
my $VERSION = 0.11;

my $Error = "";
my $openvpn_config_type_default = CFG_STR;
my @config_file_dirs = (
	"/etc",
	"/etc/openvpn",
	"/usr/local/etc",
	"/usr/local/etc/openvpn",
	realpath(File::Spec->catdir($FindBin::Bin, "..", "etc")),
	File::Spec->catdir($ENV{HOME}, "etc"),
);
my $config_file_default = "openvpn_client_connect_ldap.conf";

my $openvpn_config_types = {
	'comp-lzo' => CFG_STR,
	'dhcp-option' => CFG_STR_ARR,
	'echo' => CFG_STR_ARR,
	'ifconfig-push' => CFG_STR,
	'inactive' => CFG_STR,
	'ip-win32' => CFG_STR,
	'persist-key' => CFG_BOOL,
	'persist-tun' => CFG_BOOL,
	'ping' => CFG_STR,
	'ping-exit' => CFG_STR,
	'ping-restart' => CFG_STR,
	'push-reset' => CFG_BOOL,
	'rcvbuf' => CFG_INT,
	'redirect-gateway' => CFG_BOOL,
	'route' => CFG_STR_ARR,
	'route-delay' => CFG_INT,
	'route-gateway' => CFG_STR,
	'setenv' => CFG_STR,
	'sndbuf' => CFG_STR,
	'socket-flags' => CFG_STR,
	'topology' => CFG_STR,
};

my @ovpn_env_vars = qw(
	common_name ifconfig_pool_local_ip ifconfig_pool_netmask
	ifconfig_pool_remote_ip script_type trusted_ip trusted_port
);

my $have_digest_md5 = 0;

#############################################################
#                          FUNCTIONS                        #
#############################################################

sub msg_info {
	print "INFO:    ", join("", @_), "\n";
	msg_syslog(@_);
}

sub msg_verb {
	print STDERR "VERBOSE: ", join("", @_), "\n" unless ($quiet);
}

sub msg_err {
	print STDERR "ERROR:   ", join("", @_), "\n";
	msg_syslog(@_);
}

sub msg_debug {
	print STDERR "DEBUG:   ", join("", @_), "\n" if ($ldap_debug);
}

sub msg_fatal {
	msg_err(@_);
	msg_syslog(@_);
	exit 1;
}

sub msg_warn {
	print STDERR "WARNING: ", join("", @_), "\n";
	msg_syslog(@_);
}

sub msg_syslog {
	openlog($MYNAME, 'cons,pid', "local0");
	syslog("info", "%s", join("", @_));
	closelog();
}

sub script_init {
	# check for digest::md5
	eval { require Digest::MD5; };
	$have_digest_md5 = (($@) ? 0 : 1);
}

sub file_digest {
	my ($file) = @_;
	my $r = 0;
	my $fd = undef;

	if (! defined $file) {
		$Error = "Undefined file.";
	}
	elsif (! -f $file) {
		$Error = "Non-existing file.";
	}
	elsif (! $have_digest_md5) {
		$Error = "Perl module Digest::MD5 is not available.";
	}
	elsif (! $ccd_dir_digest_check) {
		$Error = "Digest check is disabled.";
	}
	elsif (! defined($fd = IO::File->new($file, 'r'))) {
		$Error = "Unable to open file: $!.";
	} else {
		$r = 1;
	}
	
	unless ($r) {
		$Error = "Unable to compute file digest: " . $Error;
		return undef;
	}

	# read file && weed out non-valuable stuff
	my $str = "";
	while (<$fd>) {
		$_ = strip($_);
		next if (/^#/);
		next unless (length($_) > 0);
		$str .= $_ . "\n";
	}
	$fd = undef;
	
	# print STDERR "FILE DATA:\n--snip--\n$str\n--snip--\n";
	
	# compute && return digest
	my $ctx = Digest::MD5->new();
	$ctx->add($str);
	return $ctx->hexdigest();
}

sub config_load {
	my ($file) = @_;
	$Error = "";
	
	unless (-f $file && -r $file) {
		$Error = "Invalid config file: $file \n";
		return 0;
	}
	
	# load it
	do $file;
	
	if ($@) {
		$Error = "Error parsing config file '$file': $@";
		return 0;
	}
	
	return 1;
}

sub config_load_default {
	foreach my $dir (@config_file_dirs) {
		my $file = File::Spec->catfile($dir, $config_file_default);
		if (-f $file && -r $file) {
			return config_load($file);
		}
	}

	return 1;
}

sub config_default {
	my ($file) = @_;
	$file = "-" unless (defined $file);
	
	# open myself
	my $in_fd = IO::File->new($FindBin::RealScript, 'r');
	unless ($in_fd) {
		msg_fatal("Unable to open myself '$FindBin::RealScript': $!");
		exit 1;
	}
	
	# open destination
	my $out_fd = getFd($file);	
	unless (defined $out_fd) {
		msg_fatal("Unable to open file: $Error");
		exit 1;
	}
	
	my $line_start = 96;
	my $line_stop = 505;
	my $i = 0;
	while (<$in_fd>) {
		$i++;
		next if ($i < $line_start);
		last if ($i > $line_stop);
		$_ =~ s/\s+$//g;
		
		unless (length($_) > 0) {
			print $out_fd "\n";
			next
		}
		
		if (/^#\s*(die .*)/) {
			print $out_fd $1, "\n";
		}
		elsif (/^\s*1/) {
			print $out_fd $_, "\n";
		}
		elsif ($_ !~ /^\s*#/) {
			print $out_fd "# $_\n";		
		}
		else {
			print $out_fd $_, "\n";
		}
	}
	
	$in_fd = undef;
	
	unless ($out_fd->close()) {
		msg_fatal("Unable to close default configuration file: $!");
	}
	
	$out_fd = undef;
	exit 0;
}

# EOF