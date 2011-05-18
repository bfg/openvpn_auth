#!/usr/bin/perl

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

# $Id:openvpn_authd.pl 188 2007-03-29 11:39:03Z bfg $
# $LastChangedRevision:188 $
# $LastChangedBy:bfg $
# $LastChangedDate:2007-03-29 13:39:03 +0200 (Thu, 29 Mar 2007) $

use strict;
use warnings;

# must be declared here becouse of usage in fetch_modules()
#
# the following sub was written by Mark Martinec <mark.martinec@ijs.si>
# in his excellent software, called amavisd-new,
# http://www.ijs.si/software/amavisd-new
my $log = undef;

# must be declared here becouse of usage in BEGIN {}
sub fetch_modules {
	my($reason, @modules) = @_;
	my @missing;

	foreach my $mod (@modules) {
		$log->debug("Preloading module '$mod'.") if defined ($log);
		$_ = $mod;
		$_ .= /^auto::/ ? '.al' : '.pm'; s[::][/]g;
		eval { require $_; } or push(@missing, $mod);
	}

	if (@missing) {
		die "ERROR: MISSING $reason:\n" . join('', map {"\t$_\n"} @missing);
	}
	
	return 1;
}

# Begin block... the only purpose of this block is to notify user in
# nice manner how to install basic perl modules required to run this software.
BEGIN {
	my @mods = qw(
		FindBin
		IO::File
		File::Spec
		Getopt::Long
		Log::Log4perl
		Log::Dispatch
		File::Basename
		Net::Server
	);

	eval {
		fetch_modules("Basic required modules: ", @mods);
	};
	
	if ($@) {
		print STDERR "$@\n";
		print STDERR "\n";
		print STDERR "Install missing modules using your operating system package manager or by using CPAN:\n\n";
		print STDERR "perl -MCPAN -e 'install <MODULE_NAME>\n\n";
		print STDERR "    or using CPAN interactive shell\n\n";
		print STDERR "perl -MCPAN -e shell\n";
		print STDERR "\n";
		
		exit 1;
	}
};

# basic required modules
use FindBin;
use IO::File;
use File::Spec;
use Getopt::Long;
use Log::Log4perl;
use File::Basename;

# determine libdir and put it into @INC
use lib Cwd::realpath(File::Spec->catdir($FindBin::Bin,  "..", "lib"));

use vars qw(
	$MYNAME $VERSION
	$auth_backends
	$auth_order
	$chroot
	$daemon
	$daemon_host
	$daemon_port
	$daemon_user
	$daemon_group
	$daemon_maxreqs
	$daemon_serialize
	$daemon_pidfile
	$daemon_lockfile
	$daemon_min_servers
	$daemon_max_servers
	$daemon_min_spares
	$daemon_max_spares
	$hosts_allow
	$hosts_deny
	$log_config_file
	$debug
	$extra_modules
);

# my own modules
use Net::OpenVPN::Auth;
use Net::OpenVPN::AuthChain;
use Net::OpenVPN::AuthDaemon;
use Net::OpenVPN::PasswordValidator;

#############################################################
#                    Runtime variables                      #
#############################################################
$MYNAME= basename($0);
$VERSION = 0.11;

my $Error = "";
my $default_config_file = "openvpn_authd.conf";

$log = undef;				# logger object...

my $tmpdir = File::Spec->tmpdir();
my $debug_logfile = File::Spec->catfile($tmpdir, $MYNAME . ".debug.log");

my $logger_pattern_debug = "log4perl.appender.syslog.layout.ConversionPattern	= %p: %F{1}, line %L, %M{1}(): %m%n";
my $logger_pattern_normal = "log4perl.appender.syslog.layout.ConversionPattern	= %m%n";

my $logger_standard_appender = "
	log4perl.appender.syslog			= Log::Dispatch::Syslog
	log4perl.appender.syslog.name		= $MYNAME
	log4perl.appender.syslog.ident		= $MYNAME
	log4perl.appender.syslog.layout		= Log::Log4perl::Layout::PatternLayout
";

#############################################################
#   General variables (can be overrided from command line)  #
#############################################################

#############################################################
#      OpenVPN authentication daemon configuration file     #
#############################################################

# WARNING: DO NOT REMOVE THE FOLLOWING LINES:
use strict;
use warnings;

#
# GENERAL NOTES
#
# excerpt taken from configuration file of excellent opensource project
# called amavisd-new <http://www.ijs.si/software/amavisd/>
# by Mark Martinec <http://www.ijs.si/people/mark/>.
#
#  This file is a normal Perl code, interpreted by Perl itself.
#  - make sure this file (or directory where it resides) is NOT WRITABLE
#    by mere mortals, otherwise it represents a severe security risk!
#  - for values which are interpreted as booleans, it is recommended
#    to use 1 for true, and 0 or undef or '' for false.
#  - Perl syntax applies. Most notably: strings in "" may include variables
#    (which start with $ or @); to include characters @ and $ in double
#    quoted strings, precede them by a backslash; in single-quoted strings
#    the $ and @ lose their special meaning, so it is usually easier to use
#    single quoted strings. Still, in both cases backslash needs to be doubled.
#

# AuthStruct validation functions
#
# If you use AuthStruct authentication module
# and you wrote your validation functions in some file
# (see sample_validation_functions.conf for examples),
# you can load them here.
#
# NOTE: This file is evaluated before entering chroot jail
#       (if requested; see configuration directive $chroot).
#
# Be shure to put load_validators option before $auth_backends
# configuration directive, otherwise you won't be able to specify
# validation function into $auth_backends.
#
# load_validators("/path/to/filename");

# Authentication module definition
#
# Run openvpn_authd.pl --list for list of supported authentication backends
# Run openvpn_authd.pl --doc <DRIVER> for complete driver documentation
#
# SYNTAX:
# $auth_backends = {
#
#   # backend name can be anything, but it must
# 	# unique for each declared module
#   auth_backend_1 => {
#
# 		# is successful authentication result by
# 		# this module sufficient for successful
# 		# authentication response?
# 		sufficient => 0 | 1,
#
# 		# is successful authentication result
# 		# required condition for successful
#		# authentication response?
#		# 
# 		# Set this to 1 if you declare multiple
# 		# authentication modules and you want
# 		# that this module must always return successful
# 		# authentication response in order to check other
# 		# authentication modules in authentication chain. 
#		# 
# 		required => 0 | 1,
#
#		# authentication backend driver
#		# 
#		# For list of available drivers run
#		# openvpn_authd.pl --list
#		driver => "ModuleDriverName",
#
#		# Each driver accepts/requires different
# 		# driver parameters in order to function
# 		# correctly. For list and description
# 		# of driver parameters, run
# 		# openvpn_authd.pl --doc DRIVER_NAME
#		driver_param1 => "value1",
# 		driver_param2 => "value2",
# 		driver_paramN => "valueN",
# 	},
#
# 	auth_backend_2 => {
#		# You can specify as many authentication backends
# 		# as you want. You can even specify multiple authentication
# 		# modules with unique names, but with the same driver, for
#		# example, you want to authenticate your users from
#		# 3 ldap servers (all of them with completely different setups).
#	},
#
# };
#
# Run openvpn_authd.pl --doc <DRIVER> for complete list of configuration 
# properties and configration examples.
#
# EXAMPLE:
#
# $auth_backends = {
#
# 	allow => {
#		# BE EXTREMELY CAREFUL
#		# WITH THIS BACKEND.
#		# USE FOR TESTING PURPOSES ONLY!
# 		driver => 'Allow',
#
#		sufficient => 0,
# 		required => 0, 		 
# 	},
#
# 	deny => {
#		# IT IS GOOD IDEA TO PUT THIS
#		# BACKEND AT THE END OF THE AUTH CHAIN
#		# IN $auth_order.
#		# However, this is default behaviour. 
# 		driver => 'Deny',
#
#		sufficient => 0,
# 		required => 0, 		
# 	},
#
# 	ldap_service => {
# 		driver => 'LDAP',
#
#		sufficient => 1,
# 		required => 0,
#		auth_method => 'search',
#		host => 'ldap.example.org',
#		tls => 1,
#		search_basedn => 'ou=openvpn,dc=example,dc=org',
#		search_filter => '(&(objectClass=openVPNUser)(uid=%{username})(active=TRUE))',
#		search_scope => 'sub',
#		timeout => 2
# 	},
#
# 	kerberos_service => {
# 		driver => 'Krb5',
#
#		sufficient => 1,
# 		required => 0, 		 		
# 		realm => 'EXAMPLE.ORG'
# 	},
#
# 	flat_file => {
# 		driver => 'File',
#
#		sufficient => 1,
# 		required => 0, 
#		file => '/path/to/passwd.txt',
#		password_hash => 'CRYPTMD5'
# 	},
#
# 	imap_server => {
# 		driver => 'IMAP',
#
#		sufficient => 0,
# 		required => 0,
#		host => 'imap.example.org',
#		tls => 1,
#		tls_version => 'tlsv1'
# 	},
#
# 	pop3_server => {
# 		driver => 'POP3',
#
#		sufficient => 0,
# 		required => 0, 		
#		host => 'pop3.example.org'
#		tls => 1,
#		tls_version => 'tlsv1'
# 	},
#
# 	pam_lib => {
# 		driver => 'PAM',
#
#		sufficient => 0,
# 		required => 0,
# 		pam_service => 'openvpn'
# 	},
#
#	# MySQL example
# 	sql_mysqldb => {
# 		driver => 'DBI',
#
#		sufficient => 1,
# 		required => 0,
#		dsn => 'DBI:mysql:database=openvpn;hostname=127.0.0.1;port=3308',
# 		username => 'db_user',
# 		password => 'db_pass',
# 		sql => 'SELECT pass FROM some_table WHERE user = %{username}',
# 		password_hash => 'CRYPTMD5'
# 	},
#
#	# PostgreSQL example
# 	sql_pgdb => {
# 		driver => 'DBI',
#
#		sufficient => 1,
# 		required => 0,
#		dsn => 'DBI:Pg:database=openvpn;hostname=127.0.0.1;port=5433',
# 		username => 'db_user',
# 		password => 'db_pass',
# 		sql => 'SELECT pass FROM some_table WHERE user = %{username}',
# 		password_hash => 'CRYPTMD5'
# 	},
#
# 	sasl_lib => {
# 		driver => 'SASL',
#
#		sufficient => 0,
# 		required => 0,
# 		sasl_service => 'openvpn' 
# 	},
#
# 	validator => {
# 		driver => 'AuthStruct',
#
# 		required => 1,
# 		username => \ &sample_username_validator,
# }
#
# };
#
# NOTE: All authentication backends are initialized before
#       entering chroot jail (if requested;
#       see configuration directive $chroot).
#
# Command line parameter: cannot be specified by command line
# Type: hash reference
# Default: {} (empty hash ref)
$auth_backends = {};

# Authentication module usage order.
#
# This configuration directive defines order in which
# authentication backends, defined in $auth_backends
# are used.
# 
# OpenVPN authentication daemon initializes only those
# authentication backends, which names are found in
# $auth_order, therefore you can define as many backends
# as you want in $auth_backends, but use only few of them.
# 
# SYNTAX: 
# $auth_order = [
# 	"auth_backend_2",
# 	"auth_backend_1",
# 	"auth_backend_3"
# ];
#
# In the above example authentication chain consists from
# 'auth_backend2', 'auth_backend_1', 'auth_backend3' authentication
# backends, which must be defined in $auth_backends. When authentication
# starts, daemon first checks if 'auth_backend2' returns successfull
# authentication, and then checks if this is required authentication backend
# (see authentication backend parameter 'required') and if backend is required,
# then checks next authentication backend (in our case 'auth_backend_1'), otherwise
# just returns successfull authentication result. If authentication in authentication
# backend 'auth_backend_2' fails and backend has not set 'required' flag, the next
# authentication backend from authentication chain is probed. If first backend
# returns successful authentication response and has 'sufficient' flag set, successful
# authentication response is returned immediately to authentication client.
#
# Empty $auth_order (empty authentication chain) always returnes unsuccessful
# authentication response to authentication client.
#
# Command line parameter: cannot be specified by command line
# Type: array reference
# Default: [] (empty array ref)
$auth_order = [];

# Change root directory (chroot) after server startup?
#
# Setting this value requires you to start
# authentication daemon as superuser (root).
# This option is completely ignored on Win32
# platform.
# 
# For maximum security, run authentication
# daemon in chrooted environment and set 
# $user, $group directives to non-privileged
# user/group.
#
# NOTE: Running in chroot environment sometimes
# requires placing several files into chroot jail,
# depending on your operating system.
#
# You'll possibly need:
#   - <chroot>/dev/log syslog listening socket
#   - <chroot>/etc/{services,protocols,networks,nsswitch.conf,host.conf,resolv.conf},
#     <chroot>/lib/libnss_{resolv,compat,files,dns}.so.* (Linux)
#     for any authentication backends, that require network connections
#     (LDAP, DBI, IMAP, POP3, Krb5)
#   - <chroot>/etc/krb5.conf for Krb5 authentication module
#
# Command line parameter: -t | --chroot
# Type: string
# Default: undef (don't chroot)
$chroot = undef;

# Fork into background and become daemon?
#
# Command line parameter: -d | --daemon
# Type: boolean
# Default: 0
$daemon = 0;

# Daemon listening address or UNIX domain
# listening socket path. If you want to use
# UNIX domain sockets, path must start with
# '/' character.
#
# Command line parameter: -H | --listen-addr
# Type: string
# Default: "*" (listen on all addresses using tcp socket)
$daemon_host = "*";

# Daemon listening port when using tcp
# listening sockets. This setting is quietly
# ignored if UNIX domain sockets are in use.
#
# Command line parameter: -P | --port
# Type: integer
# Default: 1559
$daemon_port = 1559;
		
# Change uid after server startup.
#
# Command line parameter: -u | --user
# Type: string
# Default: undef (don't change uid)
$daemon_user = undef;

# Change gid after server startup.
#
# Command line parameter: -g | --group
# Type: string
# Default: undef (don't change gid)
$daemon_group = undef;

# Maximum number of authentication requests
# served by single authentication worker
#
# Command line parameter: --max-requests
# Type: integer
# Default: 100
$daemon_maxreqs = 100;

# Daemon serialization method
#
# Valid values: semaphore, flock, pipe
#
# Command line parameter: -S | --serialize
# Type: string
# Default: "semaphore"
$daemon_serialize = "semaphore";

# Daemon pid file
#
# Command line parameter: -p | --pid-file 
# Type: string
# Default: "/tmp/openvpn_authd.pl.pid"
$daemon_pidfile = File::Spec->catfile(File::Spec->tmpdir(), $MYNAME . ".pid");

# Daemon serialization lock file
#
# Command line parameter: -l | --lock-file
# Type: string
# Default: "/tmp/openvpn_authd.pl.lock"
$daemon_lockfile = File::Spec->catfile(File::Spec->tmpdir(), $MYNAME . ".lock");

# Minimum number of authentication worker servers
#
# Command line parameter: --min-servers
# Type: integer
# Default: 1
$daemon_min_servers = 1;

# Maximum number of authentication worker servers
#
# Command line parameter: --max-servers
# Type: integer
# Default: 10
$daemon_max_servers = 10;

# Minimum number of spare worker servers
#
# Command line parameter: --min-spares
# Type: integer
# Default: 1
$daemon_min_spares = 1;

# Maximum number of spare worker servers
#
# Command line parameter: --max-spares
# Type: integer
# Default: 1
$daemon_max_spares = 1;

# Allowed/denied authentication client hosts.
#
# If allow or deny options are given, the incoming client
# must match a $hosts_allow and not match a $hosts_deny
# or the client connection will be closed.
#
# NOTE: These two directives are completely
#       ignored when authentication daemon accepts
#       connections via unix domain socket.
#
# Type: array reference
# Default: [] (empty array reference, no allowed/denied hosts)
$hosts_allow = [];
$hosts_deny = [];

# Log::Log4perl logging configuration file
#
# Basic syslog logging, suitable for most users is
# already built-in openvpn_authd. If you want really
# customize it, or send logging output to somewhere
# else than syslog, just create Log4perl configuration
# file and specify it here.
#
# Command line parameter: -L | --log-config
# Type: string
# Default: undef (use built-in logging settings)
$log_config_file = undef;

# Heavy daemon and backend library debugging.
# Use only when you're in trouble :)
#
# NOTE: This option is completely ignored
# when $log_config_file is set by config
# file or by command line parameter
#
# Command line parameter: -D | --debug
# Type: boolean
# Default: 0
$debug = 0;

# List of preloaded perl modules
#
# If you're running authentication daemon in chroot
# jail and you're getting error messages in log
# about missing modules, you can specify them
# here and they will be loaded before server startup.
#
# EXAMPLE:
#
# $extra_modules = [
# 	'Bit::Vector',
# 	'DBD::mysql',
# 	'DBD::Pg'
# ]; 
#
# Type: array reference
# Default: [] (don't preload any additional modules)
$extra_modules = [
	# Needed by LDAP backend:
	#
	#'IO::Socket::SSL',			# If using tls => 1
	#'Net::LDAP::Util',
	#'Net::LDAP::Bind',
	#'Net::LDAP::Search',
	#'Net::LDAP::Extension',

	# Needed by DBI backend
	#
	# 'Carp::Heavy',
	# 'DBD::mysql'				# If you're using mysql database
	# 'DBD::Pg'				# If you're using postgresql database
];

# Comment out the following line
# in order to make this configuration
# file valid
# die "...at least read the whole goddamn configuration file.\n";

# Don't remove/comment the following line
1;

# EOF

#############################################################
#                        FUNCTIONS                          #
#############################################################

my @config_file_dirs = (
	"/etc",
	"/etc/openvpn",
	"/usr/local/etc",
	"/usr/local/etc/openvpn",
	Cwd::realpath(File::Spec->catfile($FindBin::Bin,  "..", "etc"))
);

my $daemon_proto = "tcp";

sub pvar {
	my ($val, $bool) = @_;
	$bool = 0 unless (defined $bool);

	if ($bool) {
		return ((defined $val && $val == 1) ? "yes" : "no");
	} else {
		if (! defined $val) {
			return '"undefined"';
		}
		elsif ($val =~ m/^\d+$/) {
			return $val;
		}
		return "\"$val\"";
	}
}

sub printhelp {
	print STDERR "Usage: $MYNAME [OPTIONS] [DAEMON ACTION]\n";
	print STDERR "\n";
	print STDERR "This is simple authentication server, which is able to authenticate from\n";
	print STDERR "various authentication backends in the order specified in configuration file.\n\n";
	print STDERR "NOTE:\n";
	print STDERR "Some essential configuration parameters can be set only via configuration file.\n\n";
	print STDERR "DAEMON OPTIONS:\n";
	print STDERR "  -c     --config        Load configuration specified configuration file\n";
	print STDERR "                         If this parameter is not specified, then daemon will\n";
	print STDERR "                         look for configuration file named '$default_config_file'\n";
	print STDERR "                         in the following list of directories:\n";
	print STDERR "\n";
	foreach my $dir (@config_file_dirs) {
	print STDERR "                         $dir\n";
	}
	print STDERR "\n";
	print STDERR "  -d     --daemon        Fork into background after startup (Default: ", pvar($daemon, 1), ")\n";
	print STDERR "\n";
	print STDERR "  -H     --listen-addr   Listen on specified address (Default: ", pvar($daemon_host), ")\n";
	print STDERR "                         This can be valid tcp/ip address or path to unix domain socket\n";
	print STDERR "\n";
	print STDERR "  -P     --port          Listening port if listening on tcp socket (Default: ", pvar($daemon_port), ")\n";
	print STDERR "  -u     --user          Change uid to specified user after startup (Default: ", pvar($daemon_user), ")\n";
	print STDERR "  -g     --group         Change gid to specified group after startup (Default: ", pvar($daemon_group), ")\n";
	print STDERR "\n";
	print STDERR "         --max-requests  Maximum number of requests served by worker (Default: ", pvar($daemon_maxreqs), ")\n";
	print STDERR "         --min-servers   Minimum number of running workers (Default: ", pvar($daemon_min_servers), ")\n";
	print STDERR "         --max-servers   Maximum number of running workers (Default: ", pvar($daemon_max_servers), ")\n";
	print STDERR "         --min-spares    Minimum number of spare workers (Default: ", pvar($daemon_min_spares), ")\n";
	print STDERR "         --max-spares    Maximum number of spare workers (Default: ", pvar($daemon_max_spares), ")\n";
	print STDERR "\n";
	print STDERR "  -S     --serialize     Daemon serialize method (Default: ", pvar($daemon_serialize), ")\n";
	print STDERR "                         Valid settings: flock, semaphore, pipe\n";
	print STDERR "\n";
	print STDERR "  -l     --lock-file     Path to lock file when using file-based serliaze method (Default: ", pvar($daemon_lockfile), ")\n";
	print STDERR "  -p     --pid-file      Path to pid file (Default: ", pvar($daemon_pidfile), ")\n";
	print STDERR "  -t     --chroot        Chroot to specified directory after server startup (Default: ", pvar($chroot), ")\n";
	print STDERR "\n";
	print STDERR "LOGGING OPTIONS:\n";
	print STDERR "  -L     --log-config    Use specified Log::Lo4perl configuration file (Default: ", pvar($log_config_file), ")\n";
	print STDERR "                         If this option is omitted, default logging to syslog will be used.\n";
	print STDERR "\n";
	print STDERR "  -D     --debug         Debug mode. Debug output is written to syslog. This switch is completely ignored\n";
	print STDERR "                         if logging configuration file is specified using --log-config switch.\n";
	print STDERR "\n";
	print STDERR "OTHER OPTIONS:\n";
	print STDERR "         --list          List supported authentication backends\n";
	print STDERR "         --doc           Show authentication backend documentation\n";
	print STDERR "         --default-conf  Prints out default configuration file\n";
	print STDERR "         --list-pwalgs   Lists supported and enabled password hashing algorithms\n";
	print STDERR "\n";
	print STDERR "  -V     --version       Print daemon version\n";
	print STDERR "  -h     --help          This help message\n";
	print STDERR "\n";
	print STDERR "DAEMON ACTIONS:\n";
	print STDERR "         start           Start daemon (default)\n";
	print STDERR "         stop            Stop daemon\n";
	print STDERR "         restart         Restart daemon\n";
	print STDERR "         status          Obtain daemon status\n";
}

sub get_logger_config {
	# if we have logging configuration file, we should just return
	# it...
	return $log_config_file	if (defined $log_config_file);

	# build appenders string...	
	my $str = $logger_standard_appender;
	
	# compute root logger
	my $root_logger = "\tlog4j.rootLogger=";
	if ($debug) {
		$root_logger .= "ALL,syslog";
		$str .= "\t" . $logger_pattern_debug;
	} else {
		$root_logger .= "INFO,syslog";
		$str .= "\t" . $logger_pattern_normal;
	}
	
	# join together
	$str = $root_logger . "\n\n" . $str;
	
	# return reference
	return \ $str;
}

sub logger_init {
	my ($action) = @_;
	my $cfg = get_logger_config();

	# if ($debug) {
	# 	print "Logger config:\n\n$$cfg\n\n";
	# }
	
	eval {
		Log::Log4perl->init($cfg);
	};

	if ($@) {
		print STDERR "Unable to initialize Log4perl logging subsystem: $@\n";
		exit 1;
	}
	
	my $obj = Log::Log4perl->get_logger(__PACKAGE__);
	$obj->info(sprintf("%s version %-.2f startup [%s].", $MYNAME, $VERSION, $action));
	$obj->info("Logging subsystem initialized.");
	return $obj;
}

sub load_config_file {
	my ($file) = @_;
	$Error = "";
	unless (-f $file && -r $file) {
		$Error = "Config file '$file' is not a file, does not exist or is not readable.";
		return 0;
	}
	
	# read it
	no warnings;
	do $file;
	
	if ($@) {
		$Error = "Syntax error in config file '$file': $@";
		$Error =~ s/\s+$//g;
		return 0;
	}
	
	return 1;
}

sub load_config_default {
	foreach my $dir (@config_file_dirs) {
		my $f = File::Spec->catfile($dir, $default_config_file);
		if (-f $f && -r $f) {
			unless (load_config_file($f)) {
				print STDERR "Unable to load configuration file '$f': $Error\n";
				exit 1;
			}
		}
	}
}

sub load_validators {
	my ($file) = @_;
	$Error = "";
	$log->debug("Loading validation functions from file '$file'.") if (defined $log);
	unless (-f $file && -r $file) {
		die "Validation functions file '$file' is not a file or does not exist.\n";
	}
	
	# read it
	no warnings;
	do $file;
	die "Syntax error in validator file '$file': $@" if ($@);
	$log->debug("Validation functions were successfully loaded.") if (defined $log);

	return 1;
}

sub chain_prepare {
	$Error = "";
	my $chain = Net::OpenVPN::AuthChain->new();
	unless (@{$auth_order}) {
		$Error = "Empty authentication order variable.";
		return undef;
	}

	# push auth modules into auth chain
	foreach my $key (@{$auth_order}) {
		$log->debug("Initializing chain module '$key'.");
		unless (exists($auth_backends->{$key})) {
			$Error = "Undefined authentication backend '$key'. You haven't specify it in \$auth_backends, have you? :)";
			return undef;
		}
		unless (exists($auth_backends->{$key}->{driver})) {
			$Error = "Unable to create authentication module '$key': Driver is not defined.";
			return undef;
		}
		my $drv = $auth_backends->{$key}->{driver};
		delete($auth_backends->{$key}->{driver});
		$log->debug("Initializing chain module '$key' with driver '$drv'.");
		my $obj = Net::OpenVPN::Auth->factory($drv, %{$auth_backends->{$key}});
		unless (defined $obj) {
			$Error = "Unable to create authentication module '$key': " . Net::OpenVPN::Auth->getError();
			return undef;
		}
		$obj->setName($key);
		$log->debug("Assigning initialized chain module '$key' to authentication chain.");
		unless ($chain->pushModule($obj)) {
			$Error = "Unable to assign authentication module '$key': " . $chain->getError();
			return undef;
		}
	}
	
	if ($log->is_debug()) {
		$log->debug("Authentication chain contains the " . $chain->getNumModules() . " modules.");
	}

	return $chain;
}

sub daemon_action_start {
	print "Starting ${MYNAME}...\n";
	
	# check if daemon is already running...
	my $pid = daemon_action_status(1);
	if ($pid) {
		print STDERR "Daemon is already running as pid $pid.\n";
		return 0;
	}

	# initialize chain object
	my $chain = undef;
	unless (defined ($chain = chain_prepare())) {
		print STDERR "Error preparing authentication chain: $Error\n";
		return 0;
	}

	# initialize server object
	my $srv = Net::OpenVPN::AuthDaemon->new();
	$srv->setName($MYNAME);

	# assign auth chain to server module
	unless ($srv->setChain($chain)) {
		print STDERR "Unable to assign authentication chain to server object: ", $srv->getError(), "\n";
		return 0;
	}

	# build server parameter hash
	my %srv_args = (
		# listen options
		host => $daemon_host,
		port => ($daemon_host =~ /^\//) ? $daemon_host : $daemon_port,
		proto => ($daemon_host =~ /^\//) ? "unix" : "tcp",
	
		# daemon options
		user => $daemon_user,
		group => $daemon_group,
		max_requests => $daemon_maxreqs,

		serialize => $daemon_serialize,
		pid_file => $daemon_pidfile,
		lock_file => $daemon_lockfile,
		
		min_servers => $daemon_min_servers,
		max_server => $daemon_max_servers,
	
		min_spare_servers => $daemon_min_spares,
		max_spare_servers => $daemon_max_spares,

		chroot => (defined $chroot && length($chroot) > 0) ? $chroot : undef,
		background => ($daemon) ? 1 : undef,
		setsid => ($daemon) ? 1 : undef,

		# stdout is not directly tied to client...
		no_client_stdout => 1,
	
		# log level
		log_level => ($debug) ? 4 : 2,
	);

	# serialization mess...
	delete $srv_args{lock_file} if ($daemon_serialize ne 'flock');
	if ($daemon_serialize eq 'semaphore') {
		push(@{$extra_modules}, 'IPC::SysV', 'IPC::Semaphore');
	}

	# apply CIDR acess controls
	# on non-unix domain listening sockets.
	if ($daemon_host !~ m/^\//) {
		if ($#{$hosts_allow} >= 0) {
			push(@{$extra_modules}, "Net::CIDR");
			$srv_args{cidr_allow} = $hosts_allow;
		}
		if ($#{$hosts_deny} >= 0) {
			push(@{$extra_modules}, "Net::CIDR");
			$srv_args{cidr_deny} = $hosts_deny;
		}
	}

	# preload modules, if we're going to enter chroot jail
	if ($chroot) {
		# perl version < 5.8.0?
			push(@{$extra_modules}, 'auto::POSIX::setgid', 'auto::POSIX::setuid') if ($] < 5.008);
	}

	fetch_modules("Required modules", @{$extra_modules});

	unless ($daemon) {
		print STDERR sprintf("NOTE: Starting %s %-.2f in foreground.\n", $MYNAME, $VERSION);
		print STDERR "\n";
		print STDERR "NOTE: No output except pid file notice is expected to be printed to console.\n";
		print STDERR "NOTE: If daemon exits immediately, server startup failed. See log(s) for details.\n\n";
	}

	# change umask in case we're using unix domain sockets
	# we want that anyone would be able to write
	# to unix domain sockets...
	$srv->{umask} = umask();
	umask(000);

	# start the authentication server
	$srv->run(%srv_args);

	return 1;
}

sub daemon_action_stop {
	print "Stopping ${MYNAME}...\n";
	my $pid = get_pid($daemon_pidfile);
	unless ($pid) {
		print STDERR "$Error\n";
		return 0;
	}
	
	# kill the bastard
	my $num = 0;
	my $i = 0;
	my $x = 0;
	while (($x = kill(15, $pid)) > 0 && $i < 3) {
		$num += $x;
		sleep(1);
	}

	return ($num > 0) ? 1 : 0;
}

sub daemon_action_restart {
	return (daemon_action_stop() && daemon_action_start());
}

sub daemon_action_status {
	my ($silent) = @_;
	$silent = 0 unless (defined $silent);

	my $pid = get_pid($daemon_pidfile);
	unless ($pid) {
		print "$MYNAME is stopped: $Error\n" unless ($silent);
		return 0;
	}

	# check if process is alive
	unless (kill(0, $pid)) {
		print "$MYNAME is stopped.\n" unless ($silent);
		# remove dead pid file
		unlink($daemon_pidfile);
		return 0;
	}

	# report status
	print "$MYNAME is running as pid $pid.\n" unless ($silent);
	return $pid; 
}

sub daemon_action {
	my ($action) = @_;
	$action = "start" unless (defined $action);

	my $r = undef;
	my $str = "daemon_action_" . $action;
	# safely run action
	my $code = \ & {$str}; 
	eval {
		$r = &$code();
	};

	if ($@) {
		print STDERR "Invalid daemon action '$action'.\n";
		return 0;
	}

	return $r;
}

sub get_pid {
	my ($file) = @_;
	my $pid = get_pid_file($file);

	# check if pid is alive
	if ($pid) {
		unless (kill(0, $pid)) {
			print STDERR "WARNING: Pid read from pidfile '$file' is not alive. Trying do determine $MYNAME pid using ps(1).\n";
			return get_pid_ps();
		}
		
		return $pid;
	} else {
		print STDERR "WARNING: Trying do determine $MYNAME pid using ps(1).\n";
		return get_pid_ps();
	}

	return 0;
}

sub get_pid_file {
	my ($file) = @_;
	$file = $daemon_pidfile unless (defined $file);
	
	unless (-f $file && -r $file) {
		print STDERR "WARNING: Pid file '$file' does not exist, is not readable or is not a plain file.\n";
		return 0;
	}

	$Error = "";

	my $fd = IO::File->new($file, 'r');
	unless (defined $fd) {
		$Error = "Unable to read file '$file': $!";
		return 0;
	}

	my $line = $fd->getline();
	# remove anything but digits.
	$line =~ s/[^0-9]+//g;
	$fd->close();
	$fd = undef;

	return $line;
}

sub get_pid_ps {
	my $fd = undef;
	unless (open($fd, "ps -ef |")) {
		$Error = "Error: Unable to open pipe to ps(1) command: $!";
		return 0;
	}
	
	# read the whole thing
	my $pid = 0;
	while (<$fd>) {
		$_ =~ s/^\s+//g;
		$_ =~ s/\s+$//g;
		my @tmp = split(/\s+/, $_);
		$pid = $tmp[1] if ($tmp[7] eq $MYNAME && $tmp[8] =~ m/master/);
	}
	close($fd);

	return $pid;
}

#############################################################
#                          MAIN                             #
#############################################################


# try to load default config file
# (but don't bother if it does not exist)
load_config_default();

# configure command line parser
Getopt::Long::Configure(
	"bundling"
);
my $r = GetOptions(
	'c|config=s' => sub {
		unless (load_config_file($_[1])) {
			print STDERR "$Error\n";
			exit 1;
		}
	},
	'd|daemon!' => \ $daemon,

	'H|listen-addr=s' => \ $daemon_host,
	'P|port=i' => \ $daemon_port,
	'u|user=s' => \ $daemon_user,
	'g|group=s' => \ $daemon_group,
	'max-requests=i' => \ $daemon_maxreqs,
	'max-servers=i' => \ $daemon_max_servers,
	'min-servers=i' => \ $daemon_min_servers,
	'max-spares=i' => \ $daemon_max_spares,
	'min-spares=i' => \ $daemon_min_spares,
	'S|serialize=s' => \ $daemon_serialize,
	'l|lock-file=s' => \ $daemon_lockfile,
	'p|pid-file=s' => \ $daemon_pidfile,
	't|chroot=s' => \ $chroot,

	'L|log-config=s' => \ $log_config_file,
	'D|debug!' => \ $debug,
	
	'list' => sub {
		print join(", ", Net::OpenVPN::Auth->getDrivers()), "\n";
		exit 0;
	},
	
	'doc=s' => sub {
		my $name = $_[1];
		$ENV{PERL5LIB} = join(":", @INC);
		system("perldoc Net::OpenVPN::Auth::$name");
		exit 0;
	},
	
	'default-conf' => sub {
		my $fd = IO::File->new($0, 'r');
		unless (defined $fd) {
			print STDERR "Unable to open '$0' for reading.\n";
			exit 1;
		}

		my $i = 0;
		while (<$fd>) {
			$i++;
			next if ($i < 168);
			last if ($i > 653);
			if ($_ =~ m/ die/) {
				$_ =~ s/^[#\s]+//g;
			}
			print $_;
		}
		exit 0;
	},
	
	'list-pwalgs' => sub {
		my $val = Net::OpenVPN::PasswordValidator->new();
		print "NAME           ENABLED MODULE                DESCRIPTION\n";	
		foreach my $alg ($val->getSupported()) {
		printf(
			"%-10.10s     %-3.3s     %-20.20s  %s\n",
			$alg,
			(($val->isEnabled($alg))? "yes" : "no"),
			$val->getRequiredModule($alg),
			$val->getDescription($alg)
		);
		
		}
		exit 0;
	},

	'V|version' => sub {
		printf("%s %-.2f\n", $MYNAME, $VERSION);
		exit 0;
	},
	'h|help' => sub {
		printhelp();
		exit 0;
	}
);

unless ($r) {
	print STDERR "Invalid command line options. Run $MYNAME --help for help.\n";
	exit 1;
}

# fetch daemon action
my $action = shift(@ARGV);
$action = "start" unless (defined $action);

# initialize logging subsystem
$log = logger_init($action);

# heh, run desired action
exit (! daemon_action($action));

# EOF