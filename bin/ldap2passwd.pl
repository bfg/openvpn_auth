#!/usr/bin/perl

# Copyright (c) 2007-2011, Brane F. Gracnar
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Interseek Ltd., Software & Media nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY Brane F. Gracnar ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Brane F. Gracnar BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

use Socket;
use IO::File;
use Net::LDAP;
use File::Spec;
use File::Copy;
use Digest::MD5;
use Getopt::Long;
use Sys::Hostname;
use File::Basename;
use POSIX qw(strftime);
use File::Temp qw(tempfile);

use constant HAVE_IPV6 => eval 'use Socket6; 1;' ? 1 : 0;

################################################
#                  GLOBALS                     #
################################################

my $verbose = 0;
my $force = 0;
my $timeout_connect = 1;
my $timeout_search = 30;
my $config_default = {
################################################
#          ldap2passwd configuration           #
################################################

# LDAP server hostname
#
# (string, "localhost")
ldap_host => "localhost",

# LDAP server port...
# (integer, 389)
ldap_port => 389,

# LDAP URI scheme
#
# Possible values:
# (string, "ldap", "ldaps", "ldapi")
ldap_scheme => "ldap",

# Use LDAP TLS secured connection?
#
# (boolean, 0)
ldap_tls => 0,

# LDAP TLS options
#
# See http://search.cpan.org/~gbarr/perl-ldap-0.39/lib/Net/LDAP.pod#start_tls
# for additional info
ldap_tls_verify => "none",
ldap_tls_sslversion => "tlsv1",
ldap_tls_ciphers => "HIGH",
ldap_tls_cafile => "",
ldap_tls_capath => "",
ldap_tls_clientcert => "",
ldap_tls_clientkey => "",
ldap_tls_checkcrl => 0,
ldap_tls_keydecrypt => "",

# LDAP bind DN
#
# (string, "")
ldap_bind_dn => "",

# LDAP bind password
#
# (string, "")
ldap_bind_pw => "",

# LDAP search base
#
# (string, "dc=example,dc=com")
search_base => "dc=example,dc=com",

# LDAP search scope
#
# Possible vaues: sub, base, one
#
# (string, "sub")
search_scope => "sub",

# LDAP search filter
#
# (string, "(objectClass=*)")
search_filter => "(objectClass=*)",

# Dereference search results...
#
# (string, "never")
search_deref => "never",

# Username LDAP entry attribute
attr_username => "cn",

# LDAP entry passwod attribute
attr_password => "userPassword",

# file permissions
#
# (string, "0600")
file_mode => "0600",

# file owner/group
#
# If specified (optional) file ownership will be changed
# after file deployment.
#
# Possible values: "<user>:<group>", "<user>"
#
# (string, "")
file_user_group => "",

# EOF
};

################################################
#                 FUNCTIONS                    #
################################################
my $MYNAME = basename($0);
my $VERSION = '0.14';
my $Error = "";

my $config = {};

sub msg_err {
	push(@_, $Error) unless (@_);
	print STDERR "ERROR: ", join("", @_), "\n";
}

sub msg_verbose {
	return 1 unless ($verbose);
	print STDERR "VERBOSE: ", join("", @_), "\n";
}

sub msg_warn {
	print STDERR "WARNING: ", join("", @_), "\n";
}

sub msg_fatal {
	push(@_, $Error) unless (@_);
	print STDERR "FATAL: ", join("", @_), "\n";
	exit 1;
}

sub msg_info {
	print "INFO:  ", join("", @_), "\n";
}

sub config_default_print {
	my $fd = IO::File->new($0, 'r');
	return 0 unless (defined $fd);

	my $i = 0;
	while (($i < 145) && defined (my $l = <$fd>)) {
		$i++;
		next if ($i < 54);
		$l = trim($l);
		$l =~ s/,*\s*$//g;
		$l =~ s/=>/=/g;
		print $l, "\n";

	}
}

sub trim {
	my ($str) = @_;
	return undef unless (defined $str);
	$str =~ s/^\s+//g;
	$str =~ s/\s+$//g;
	return $str;
}

sub qtrim {
	my ($str) = @_;
	return undef unless (defined $str);
	$str =~ s/^\s*["']*//g;
	$str =~ s/["']*\s*$//g;
	return $str;
}

sub config_read {
	my ($file) = @_;
	unless (defined $file && length($file)) {
		$Error = "Unspecified configuration file.";
		return undef;
	}
	msg_verbose("Trying to parse configuration file: $file");
	my $fd = IO::File->new($file, 'r');
	unless (defined $fd) {
		$Error = "Error opening configuration file '$file': $!";
		return undef;
	}
	
	my $cfg = {};
	# copy defaults...
	%{$cfg} = %{$config_default};
	
	# read file...
	my $i = 0;
	while (($i < 1000) && defined (my $line = <$fd>)) {
		$i++;
		$line = trim($line);

		# skip empty lines and comments...
		next unless (length($line) > 0);
		next if ($line =~ m/^#/);
		
		# wipe out inline comments...
		my ($l, undef) = split(/\s*#+\s*/, $line);
		$line = trim($l);
		
		my ($k, $v) = split(/\s*=\s*/, $line, 2);
		$k = trim($k);
		$v = qtrim($v);

		if (exists($cfg->{$k})) {
			#msg_verbose("Setting configuration parameter '$k' => '$v'");
			$cfg->{$k} = $v;
		} else {
			#msg_verbose("Ignoring unsupported configuration parameter '$k'");
		}
	}

	return $cfg;
}

sub process_username {
	my ($str) = @_;
	return trim($str);
}

sub process_password {
	my ($str) = @_;
	return undef unless (defined $str && length($str) > 0);
	$str =~ s/^{[^}]+}//g;
	return $str;
}

sub resolve_host {
	my ($name, $no_ipv6) = @_;
	$no_ipv6 = 0 unless (defined $no_ipv6);
	return () unless (defined $name);

	my @res = ();
	if (HAVE_IPV6 && ! $no_ipv6) {
		no strict;
		my @r = getaddrinfo($name, 1, AF_UNSPEC, SOCK_STREAM);
		return () unless (@r);
		while (@r) {
			my $family = shift(@r);
			my $socktype = shift(@r);
			my $proto = shift(@r);
			my $saddr = shift(@r);
			my $canonname = shift(@r);
			next unless (defined $saddr);

			my ($host, undef) = getnameinfo($saddr, NI_NUMERICHOST | NI_NUMERICSERV);
			push(@res, $host) if (defined $host);
		}
	} else {
		my @addrs = gethostbyname($name);
		@res = map { inet_ntoa($_); } @addrs[4 .. $#addrs];
	}

	# assign system error code...
	$! = 99 unless (@res);

	return @res;
}

sub ldap_connect {
	my $conn = undef;

	my $ldap_url = $config->{ldap_host};
	my %opt = (
		port => $config->{ldap_port},
		scheme => $config->{ldap_scheme},
		timeout => $timeout_connect,
		version => 3,
		inet6 => 1,
	);

	# ldap url?
	if ($ldap_url =~ m/^ldap(s)?:\/\//i) {
		$conn = Net::LDAP->new($ldap_url, %opt);
	} else {
		# resolve all ldap addresses...
		my @ldap_addrs = resolve_host($config->{ldap_host});
		unless (@ldap_addrs) {
			$Error = "Unable to resolve LDAP server '$config->{ldap_host}': $!";
			return undef;
		}
		msg_verbose("LDAP host '$config->{ldap_host}' resolved to: ", join(", ", @ldap_addrs));

		while (@ldap_addrs) {
			my $host = shift(@ldap_addrs);
			next unless (defined $host);
			# try to connect...
			msg_verbose("Connecting to LDAP server '$config->{ldap_host}:$config->{ldap_port} using address $host.");
			$conn = Net::LDAP->new($host, %opt);
			last if (defined $conn);
		}
	}
	
	unless (defined $conn) {
		$Error = "Unable to connecto to LDAP server '$config->{ldap_host}:$config->{ldap_port}': $!";
		return undef;
	}
	msg_verbose("Successfully connected to LDAP server.");
	
	# start tls if necessary...
	if ($config->{ldap_tls}) {
		# build start_tls option hash...
		my %opt = ();
		map {
			if ($_ =~ m/^ldap_tls_(.+)/) {
				$opt{$1} = $config->{$_};
			}
		} keys %{$config};
		if (exists($opt{keydecrypt}) && length($opt{keydecrypt})) {
			my $pw = $opt{keydecrypt};
			$opt{keydecrypt} = sub { return $pw }; 
		}

		msg_verbose("Starting TLS.");
		my $r = $conn->start_tls(%opt);
		if (! defined $r || $r->is_error()) {
			$Error = "Error establishg TLS connection: " . $r->error();
			return undef;
		}
		msg_verbose("Successfully started TLS session.");
	}
	
	my $ldap_binddn = $config->{ldap_bind_dn};
	my $ldap_bindpw = $config->{ldap_bind_pw};
	
	# possibly bind...
	if (defined $ldap_binddn && defined $ldap_bindpw && length($ldap_binddn) > 0 && length($ldap_bindpw) > 0) {
		my %opt = (
			password => $ldap_bindpw,
		);
		msg_verbose("Binding LDAP server as DN '$ldap_binddn'");
		my $r = $conn->bind($ldap_binddn, %opt);
		if (! defined $r || $r->is_error()) {
			$Error = "Error binding LDAP directory as '$ldap_binddn': " . $r->error();
			return undef;
		}
		msg_verbose("LDAP bind successful.");
	}

	# this is it!
	return $conn;
}

sub get_data {
	# connect to ldap directory...
	my $conn = ldap_connect();
	return undef unless (defined $conn);
	
	# perform search...
	my $attrs = [ $config->{attr_username}, $config->{attr_password} ];
	my $search_sizelimit = undef;
	my $search_timelimit = 100;
	my $search_deref  = "never";
	my %opt = (
		base => $config->{search_base},
		scope => $config->{search_scope},
		deref => $config->{search_deref},
		timelimit => $timeout_search,
		filter => $config->{search_filter},
		attrs => $attrs,
	);

	msg_verbose("Performing LDAP search.");
	my $ts = time();
	my $r = $conn->search(%opt);
	if ($r->is_error()) {
		$Error = "Error performing LDAP search: " . $r->error();
		return undef;
	}
	my $duration = time() - $ts;
	
	msg_verbose("Found " . $r->count() . " LDAP entries after $duration second(s).");
	
	# retrieve data...
	my $data = {};
	while (defined (my $entry = $r->shift_entry())) {
		my $user = $entry->get_value($config->{attr_username}, alloptions => 0, asref => 0);
		my $pass = $entry->get_value($config->{attr_password}, alloptions => 0, asref => 0);
		$user = process_username($user);
		$pass = process_password($pass);
		next unless (defined $user && defined $pass);
		$data->{$user} = $pass;
	}
	
	return $data;
}

sub tmppw_write {
	my ($data) = @_;
	my ($fd, $file) = tempfile(
		File::Spec->catfile(
			File::Spec->tmpdir(),
			$MYNAME . ".XXXXXX",
		),
		UNLINK => 0,
	);
	unless (defined $fd) {
		$Error = "Unable to create temporary file: $!";
		return undef;
	}
	
	# write header
	print $fd "#\n";
	print $fd "# This file was generated by ", sprintf("%s version %-.2f", $MYNAME, $VERSION), "\n";
	print $fd "#\n";
	printf $fd "# %-15.15s %s\n", "Date:", strftime("%Y/%m/%d %H:%M:%S", localtime(time()));
	printf $fd "# %-15.15s %s\n", "Host:", hostname();
	print $fd "#\n";
	printf $fd "# %-15.15s %s\n", "LDAP server:", "$config->{ldap_host}:$config->{ldap_port}";
	printf $fd "# %-15.15s %s\n", "Search base:", "$config->{search_base}";
	printf $fd "# %-15.15s %s\n", "Search scope:", "$config->{search_scope}";
	printf $fd "\n";
	
	# write data
	map {
		print $fd $_, ":", $data->{$_}, "\n";
	} sort keys %{$data};
	
	# write footer
	print $fd "\n";
	print $fd "# EOF\n";
	
	# close file
	$fd = undef;
	
	return $file;
}

sub raw_checksum {
	my ($file) = @_;
	return undef unless (defined $file && length($file) > 0);
	my $fd = IO::File->new($file, 'r');
	return undef unless (defined $fd);
	
	# compute data checksum...
	my $ctx = Digest::MD5->new();
	while (defined (my $line = <$fd>)) {
		next if ($line =~ m/^#/);
		$ctx->add($line);
	}

	return $ctx->hexdigest();
}

sub uid_get {
	my ($user) = @_;
	my @tmp = getpwnam($user);
	return undef unless (@tmp);
	return $tmp[2];
}

sub uid_get_gid {
	my ($user) = @_;
	my @tmp = getpwnam($user);
	return undef unless (@tmp);
	return $tmp[3];
}

sub gid_get {
	my ($group) = @_;
	my @tmp = getgrnam($group);
	return undef unless (@tmp);
	return $tmp[2];
}

sub run {
	my ($file) = @_;
	unless (defined $file && length($file) > 0) {
		msg_verbose("No output file was given, will write output to stdout.");
		$file = "-";
	}
	
	# get data
	my $data = get_data();
	return 0 unless (defined $data);
	
	# write data to tmpfile
	my $tmpfile = tmppw_write($data);
	return 0 unless (defined $tmpfile);
	
	# return result...
	my $r = 1;
	
	# should we deploy this file?
	my $deploy = 1;
	unless ($force) {
		my $chksum_dst = undef;
		my $chksum_tmp = raw_checksum($tmpfile);
		if (-f $file) {
			$chksum_dst = raw_checksum($file);
		}

		# check checksums...
		if (defined $chksum_dst && defined $chksum_tmp) {
			#msg_verbose("Checksum tmp: '$chksum_tmp'");
			#msg_verbose("Checksum dst: '$chksum_dst'");
			if ($chksum_dst eq $chksum_tmp) {
				msg_verbose("Temporary file content checksum equals destination file checksum; skipping deploy.");
				$deploy = 0;
			}
		}
	}

	if ($deploy) {
		msg_verbose("Deploying '$tmpfile' => '$file'");
		if ($file eq '-') {
			my $fd = IO::File->new($tmpfile, 'r');
			goto outta_run unless $fd;
			print while <$fd>;
		} else {
			# copy if not a file
			unless (copy($tmpfile, $file)) {
				$Error = "Unable to copy file '$tmpfile' => '$file': $!";
				$r = 0;
				goto outta_run;
			}
		}
		
		if ($file ne "-") {
			# chmod
			unless(chmod(oct($config->{file_mode}), $file)) {
				$Error = "Unable to change file permissions to '$config->{file_mode}': $!";
				$r = 0;
				goto outta_run;
			}
			
			# chown
			if (defined $config->{file_user_group} && length($config->{file_user_group})) {
				my ($user, $group) = split(/\s*:+\s*/, $config->{file_user_group});
				$user = trim($user);
				$group = trim($group);
				my $uid = uid_get($user);
				my $gid = (defined $group && length($group) > 0) ? gid_get($group) : uid_get_gid($user);
				if (defined $uid && defined $gid) {
					msg_verbose("Changing ownership on file '$file' to uid/gid $uid/$gid.");
					unless (chown($uid, $gid, $file)) {
						$Error = "Unable to change ownership on file '$file' to $uid:$gid: $!";
						$r = 0;
						goto outta_run;
					}
				} else {
					$Error = "Unable to resolve uid/gid for user/group: $user/group";
					$r = 0;
					goto outta_run;
				}
			}
		}
	}

	# that's it!
	outta_run:
	unlink($tmpfile);
	return $r;
}

sub printhelp {
	print "$MYNAME [OPTIONS] [<file>]\n";
	print "\n";
	print "This script creates Apache/Nginx/passwd(5) compatible password file\n";
	print "suitable for authenticating http/OpenVPN clients.\n";
	print "\n";
	print "NOTE: LDAP must contain passwords in crypt(3) format.\n";
	print "NOTE: If file argument is omitted then output is written to stdout.\n";
	print "\n";
	print "\n";
	print "OPTIONS:\n";
	print "  -c    --config=FILE        Load specified configuration file\n";
	print "        --default-config     Prints default configuration file\n";
	print "  -f    --force              Force file deployment even if content\n";
	print "                             didn't change.\n";
	print "  -t    --timeout-connect    Specifies LDAP connect timeout (Default: $timeout_connect)\n";
	print "  -T    --timeout-search     Specifies LDAP search timeout (Default: $timeout_search)\n";
	print "  -v    --verbose            Verbose execution\n";
	print "  -V    --version            Prints script version\n";
	print "  -h    --help               This help message\n";
}

################################################
#                    MAIN                      #
################################################

# parse command line
Getopt::Long::Configure('bundling', 'gnu_compat');
my $r = GetOptions(
	'default-config' => sub {
		config_default_print(59, 150);
		exit 0;
	},
	'c|config=s' => sub {
		
		$config = config_read($_[1]);
		msg_fatal() unless (defined $config);
	},
	'f|force!' => \ $force,
	't|timeout-connect=i' => \ $timeout_connect,
	'T|timeout-search=i' => \ $timeout_search,
	'v|verbose!' => \ $verbose,
	'V|version' => sub {
		print "$MYNAME, $VERSION\n";
		exit 0;
	},
	'h|help' => sub {
		printhelp();
		exit 0;
	}
);

unless ($r) {
	print STDERR "Invalid command line options. Run $MYNAME --help for instructions.\n";
	exit 1;
}

$r = run(@ARGV);
msg_fatal() unless ($r);

exit 0;
# EOF
