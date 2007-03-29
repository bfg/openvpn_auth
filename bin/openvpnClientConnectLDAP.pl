#!/usr/bin/perl

#
# Copyright (c) 2006, Brane F. Gracnar
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

use constant CFG_BOOL => 1;
use constant CFG_STR => 2;
use constant CFG_INT => 3;
use constant CFG_STR_ARR => 4;

use vars qw(
	$schema_mapping
	$openvpn_schema_x509cn
	$ldap_server
	$randomize_host_connect_order
	$ldap_port
	$ldap_version
	$tls
	$tls_verify
	$tls_sslversion
	$tls_ciphers
	$tls_clientcert
	$tls_clientkey
	$tls_capath
	$tls_cafile
	$bind_dn
	$bind_sasl
	$bind_sasl_authzid
	$bind_sasl_mech
	$bind_pw
	$search_basedn
	$search_filter
	$search_scope
	$search_deref
	$ldap_debug
	$ldap_timeout
	$quiet
	$ccd_dir
	$ccd_dir_digest_check
	$backup_dir
	$backup_dir_purge_older_than
	$openvpn_var_server_addr
	$openvpn_var_server_netmask
);

#############################################################
#                 CONFIGURATION VARIABLES                   #
#############################################################

# OpenVPN client config dir.
# 
# Must be set to the same value as OpenVPN variable --ccd-dir.
# This option is only used when script is *NOT* called
# as --client-connect script. This is a destination directory
# for all per-client openvpn configuration files.
#
# Type: string 
# Command line: --ccd-dir
# Default: "/tmp"
$ccd_dir = "/tmp";

# Check MD5 digests of possibly existing client configuration files
# in $ccd_dir and newly created configuration files. If digests match,
# original client configuration files will not be overwritten.
#
# NOTE: This option is used only when script is not called by OpenVPN
#       server. This option requires installed Digest::MD5 perl module.
#       Script assumes this variable is set to value of 0 if md5 perl
#       module is not available.
#
# Type: boolean
# Default: 1
$ccd_dir_digest_check = 1;

# Directory for backing up any previously existing
# OpenVPN client configuration files.
#
# WARNING:
#       If this variable is empty or undefined,
#       backups ***WILL NOT BE CREATED***; 
#       original pre-existing configuration files
#       will be *** OVERWRITTEN *** !!!!
#
# NOTE: This variable applies only when this
#       script is not invoked by OpenVPN server.
#
# Type: string
# Default: "/tmp"
$backup_dir = "/tmp/backup";

# Remove files older than specified amount of seconds
# from $backup_dir.
#
# NOTE: This variable applies only when this
#       script is not invoked by OpenVPN server.
#
# NOTE: Setting this value to 0 disables backup directory
#       cleanup.
#
# Type: integer
# Default: 86400 (one day)
$backup_dir_purge_older_than = 86400;

# Comma separated list of LDAP servers.
# 
# Type: string
# Command line: -h|--ldap-server
# Default: "localhost"
$ldap_server = "localhost";

# LDAP server port
# 
# Type: integer
# Command line: -P|--ldap-port
# Default: 389
$ldap_port = 389;

# Randomize order of ldap servers to connect.
#
# In case you specified more than one host to $ldap_server
# configuration directive, or if specified host resolves to
# multiple addresses this option (when enabled - default)
# will shuffle resolved addresses.
#
# Type: boolean
# Command line: --randomize-conn
# Default: 1
$randomize_host_connect_order = 1;

# LDAP protocol version
#
# Type: integer
# Command line: --ldap-version
# Default: 3
$ldap_version = 3;

# Timeout for LDAP operations
# 
# Type: integer
# Command line: --ldap-timeout
# Default: 5
$ldap_timeout = 5;

# Debug LDAP operations
#
# Type: boolean
# Command line: --ldap-debug
# Default: 0
$ldap_debug = 0;

#############################################################
#                    SSL/TLS VARIABLES                      #
#############################################################

# Use TLS secured LDAP connection?
#
# NOTE: Enabling this option requires installed
#       IO::Socket::SSL module 
#
# Type: boolean
# Command line: -t|--tls
# Default: 0
$tls = 0;

# TLS verify certificate
#
# NOTE: See perldoc IO::Socket::SSL for more info
# 
# Type: string
# Command line: --tls-verify
# Default: "none"
$tls_verify = "none";		# See:

# TLS protocol version
#
# NOTE: See perldoc IO::Socket::SSL for more info
# 
# Type: string
# Command line: --tls-sslversion
# Default: "tlsv1"
$tls_sslversion = "tlsv1";

# Enabled TLS ciphers
#
# NOTE: See perldoc IO::Socket::SSL for more info
# 
# Type: string
# Command line: --tls-ciphers
# Default: "HIGH"
$tls_ciphers = "HIGH";

# TLS client certificate file
#
# NOTE: See perldoc IO::Socket::SSL for more info
# 
# Type: string
# Command line: --tls-clientcert
# Default: ""
$tls_clientcert = "";

# TLS client private key file
#
# NOTE: See perldoc IO::Socket::SSL for more info
# 
# Type: string
# Command line: --tls-clientkey
# Default: ""
$tls_clientkey = "";

# CA directory
#
# NOTE: See perldoc IO::Socket::SSL for more info
# 
# Type: string
# Command line: --tls-capath
# Default: ""
$tls_capath = "";

# CA certificate file
#
# NOTE: See perldoc IO::Socket::SSL for more info
# 
# Type: string
# Command line: --tls-cafile
# Default: ""
$tls_cafile = "";

#############################################################
#                  LDAP BIND VARIABLES                      #
#############################################################

# LDAP bind distiguished name
#
# NOTE: leave empty for anonymous bind
#
# Type: string
# Command line: -u|--bind-dn
# Default: ""
$bind_dn = "";

# Bind password
#
# Type: string
# Command line: -p|--bind-pw
# Default: ""
$bind_pw = "";

# Use SASL LDAP bind?
#
# NOTE: This option requires installed Authen::SASL
#       perl module
#
# Type: boolean
# Command line: --bind-sasl
# Default: 0
$bind_sasl = 0;

# SASL authzid.
#
# NOTE: This option is used only when $bind_sasl == 1
#
# Type: string
# Command line: --bind-sasl-authzid
# Default: environmental variable $USER
$bind_sasl_authzid = $ENV{USER};

# SASL authentication mechanism
#
# Type: string
# Command line: --bind-sasl-mech
# Default: "PLAIN"
$bind_sasl_mech = "PLAIN";


#############################################################
#                  LDAP SEARCH VARIABLES                    #
#############################################################

# LDAP schema object attribute which
# holds value of client's x509 certificate common name.
#
# NOTE: if you're using bundled openvpn-ldap.schema, you
#       don't need to alter this variable.
#
# Type: string
# Default: "openvpnClientx509CN"
$openvpn_schema_x509cn = "openvpnClientx509CN";

# LDAP search base
# 
# Type: string
# Command line: -b|--search-basedn
# Default: ""
$search_basedn = "";

# LDAP search filter
#
# This option specifies LDAP search filter that is used when searching
# for corresponding LDAP entries.
#
# Specified filter string can contain *MAGIC PLACEHOLDERS*, which
# are substituted with configuration variables provided by OpenVPN
# server or configuration file...
#
# SYNTAX: %{VARIABLE_NAME}
#
# When you specify magic placeholder variable, that was *NOT*
# specified by OpenVPN server or via config file using ovpn_option_safe() or
# ovpn_option(), it's value is substitued with asterix '*' character.
# 
# *** SUPPORTED MAGIC PLACEHOLDER VARIABLES ***
#
# - all OpenVPN server provided variables:
# 	common_name ifconfig_pool_local_ip ifconfig_pool_netmask
#	ifconfig_pool_remote_ip script_type 
#	trusted_ip trusted_port
#
# - all variables configured using ovpn_option() config file parameter
#
# Type: string
# Command line: -f|--search-filter
# Default: "(&(objectClass=openVPNUser)(openvpnClientx509CN=%{common_name}))"
$search_filter = "(&(objectClass=openVPNUser)(openvpnClientx509CN=%{common_name}))";

# LDAP search scope
#
# Possible values: sub, one, none 
#
# Type: string
# Command line: --search-scope
# Default: sub
$search_scope = "sub";

# Dereference LDAP search results?
#
# Possible values: never, search, find, always
#
# Type: string
# Command line: --search-deref
# Default: 
$search_deref = "never";

#############################################################
#                  MISCELLANIOUS VARIABLES                  #
#############################################################

# Quiet execution.
#
# This option applies only when script is *NOT* called
# as --client-connect script - usually when you want to
# test configuration or dump configuration for all users.
#
# Type: boolean
# Command line: -q|--quiet
# Default: 0
$quiet = 0;

# Sets OpenVPN environment variable.
#
# You can define your own OpenVPN server options using
# functions ovpn_option() and ovpn_option_safe(). Both set
# custom openvpn server option, but ovpn_option() always
# OVERWRITE any possible pre-existing option, ovpn_option_safe()
# sets the option only if it does not exist.
#
# The idea is to define custom variables, which can be then used in
# LDAP search filters as magic placeholders.
#
# SYNTAX:
#
# ovpn_option "KEY=VALUE";
# ovpn_option_safe "KEY=VALUE";
#
# *** OR ***
#
# ovpn_option "KEY" "VALUE";
# ovpn_option_safe "KEY" "VALUE";
#
# EXAMPLE:
#      $search_filter = "(&(objectClass=openVPNUser)(openvpnClientx509CN=%{common_name})(cn=%{some_silly_var}))";
#      ovpn_option "some_silly_var" "foo*";
#

# OpenVPN server variable NAME which describes it's own local
# VPN network address.
#
# NOTE: This option is only used when configuration
#       backend provides --ifconfig-push argument.
#
# WARNING: Do not alter this variable unless you really know
#          what you're doing :)
#
# Type: string
# Default: 
$openvpn_var_server_addr = "ifconfig_pool_local_ip";

# OpenVPN server variable NAME which describes it's own local
# VPN network address netmask.
#
# NOTE: This option is only used when configuration
#       backend provides --ifconfig-push argument.
#
# WARNING: Do not alter this variable unless you really know
#          what you're doing :)
#
# Type: string
# Default: 
$openvpn_var_server_netmask = "route_netmask_1";

#############################################################
#                  LDAP SCHEMA VARIABLES                    #
#############################################################

# LDAP Schema mapping
#
# This variable maps openvpn --push attributes into LDAP
# entry attributes. You don't need to alter this variable
# if you're using bundled openvpn-ldap.schema ldap schema
# extension. This is advanced configuration option. Be sure,
# that you know what you're doing, before changing
# this variable!
#
# Type: anonymous hash
$schema_mapping = {
	'comp-lzo' => 'openvpnCompLZO',
	'dhcp-option' => 'openvpnDHCPOption',
	'echo' => 'openvpnEcho',
	'ifconfig-push' => 'openvpnIfconfig',
	'inactive' => 'openvpnInactive',
	'ip-win32' => 'openvpnIPWin32',
	'persist-key' => 'openvpnPersistKey',
	'persist-tun' => 'openvpnPersistTun',
	'ping' => 'openvpnPing',
	'ping-exit' => 'openvpnPingExit',
	'ping-restart' => 'openvpnPingRestart',
	'push-reset' => 'openvpnPushReset',
	'rcvbuf' => 'openvpnRcvBuf',
	'redirect-gateway' => 'openvpnRedirectGateway',
	'route' => 'openvpnRoute',
	'route-delay' => 'openvpnRouteDelay',
	'route-gateway' => 'openvpnRouteGateway',
	'setenv' => 'openvpnSetEnv',
	'sndbuf' => 'openvpnSndBuf',
	'socket-flags' => 'openvpnSocketFlags',
	'topology' => 'openvpnTopology',
};

# COMMENT OUT the following line to make this configuration file
# valid!
# die "You haven't read instructions, have you?'";

# DO NOT REMOVE/COMMENT OUT THE FOLLOWING LINE!
1;

# EOF

#############################################################
#                    RUNTIME VARIABLES                      #
#############################################################

my $MYNAME = basename($0);
my $VERSION = 0.1;

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

sub dump_var {
	my ($var, $bool) = @_;
	$bool = 0 unless (defined $bool);
	
	if ($bool) {
		return (($var) ? "yes" : "no");
	}
	
	return '"undefined"' unless (defined $var);
	return '"' . $var . '"';
}

sub printhelp {
	print STDERR "Usage: $MYNAME [OPTIONS] [FILE]\n\n";
	print STDERR "This script can be used in conjunction with OpenVPN as --client-connect\n";
	print STDERR "script to dynamically generate client specific configuration file\n";
	print STDERR "or can be used to dump client specific configuration files as a\n";
	print STDERR "batch job from specified list of LDAP servers.\n";
	print STDERR "\n";
	
	print STDERR "CONFIGURATION OPTIONS:\n";
	print STDERR "  -c     --config             Load specified configuration file.\n";
	print STDERR "\n";
	print STDERR "Script looks for configuration named '$config_file_default' in \n";
	print STDERR "directories listed below. If file exists, it is going to be automatically\n";
	print STDERR "loaded.\n\n";
	print STDERR "CONFIGURATION DIRECTORY SEARCH ORDER:\n";
	print STDERR "\t", join ("\n\t", @config_file_dirs), "\n";
	print STDERR "\n";
	print STDERR "\n";
	print STDERR "  -d     --default-config     Prints default configuration file.\n";
	print STDERR "\n";

	print STDERR "LDAP OPTIONS:\n";
	print STDERR "  -h     --ldap-server        LDAP server address (Default: ", dump_var($ldap_server), ")\n";
	print STDERR "                              Specify list of comma separated list of LDAP servers.\n";
	print STDERR "\n";
	print STDERR "  -P     --ldap-port          Default LDAP server port (Default: ", dump_var($ldap_port), ")\n";
	print STDERR "         --randomize-conn     Randomize list of LDAP servers (Default: ", dump_var($randomize_host_connect_order, 1), ")\n";
	print STDERR "         --ldap-version       LDAP protocol version (Default: ", dump_var($ldap_version), ")\n";
	print STDERR "         --ldap-timeout       Timeout for LDAP operations (Default: ", dump_var($ldap_timeout), ")\n";
	print STDERR "         --ldap-debug         Enable LDAP operation debugging (Default: ", dump_var($ldap_debug, 1), ")\n";
	print STDERR "\n";

	print STDERR "LDAP BIND/AUTH OPTIONS:\n";
	print STDERR "  -u     --bind-dn            LDAP bind DN (Default: ", dump_var($bind_dn), ")\n";
	print STDERR "  -p     --bind-pw            LDAP bind DN password (Default: ", dump_var($bind_pw), ")\n";
	print STDERR "         --bind-sasl          Use SASL bind (Default: ", dump_var($bind_sasl, 1), ")\n";
	print STDERR "         --bind-sasl-authzid  SASL authorization ID (Default: ", dump_var($bind_sasl_authzid), ")\n";
	print STDERR "         --bind-sasl-mech     SASL mechanism (Default: ", dump_var($bind_sasl_mech), ")\n";
	print STDERR "\n";

	print STDERR "LDAP SEARCH OPTIONS:\n";
	print STDERR "  -b      --search-basedn     LDAP search base (Default: ", dump_var($search_basedn), ")\n";
	print STDERR "  -f      --search-filter     LDAP search filter (Default: ", dump_var($search_filter), ")\n";
	print STDERR "          --search-scope      LDAP search scope (Default: ", dump_var($search_scope), ")\n";
	print STDERR "          --search-deref      Dereference search results? (Default: ", dump_var($search_deref), ")\n";
	print STDERR "\n";

	print STDERR "TLS/SSL OPTIONS:\n";
	print STDERR "  -t     --tls                Use TLS/SSL secured connection (Default: ", dump_var($tls, 1), ")\n";
	print STDERR "         --tls-verify         Verify server certficate (Default: ", dump_var($tls_verify), ")\n";
	print STDERR "         --tls-sslversion     Specifies SSL version to use (Default: ", dump_var($tls_sslversion), ")\n";
	print STDERR "         --tls-ciphers        Specifies SSL encryption ciphers (Default: ", dump_var($tls_ciphers), ")\n";
	print STDERR "         --tls-clientcert     Specifies client x509 certificate file (Default: ", dump_var($tls_clientcert), ")\n";
	print STDERR "         --tls-clientkey      Specifies client x509 key file (Default: ", dump_var($tls_clientkey), ")\n";
	print STDERR "         --tls-cafile         Specifies CA x509 file (Default: ", dump_var($tls_cafile), ")\n";
	print STDERR "         --tls-capath         Specifies CA folder (Default: ", dump_var($tls_capath), ")\n";
	print STDERR "\n";
	
	print STDERR "LDAP SCHEMA OPTIONS:\n";
	print STDERR "\n";
	print STDERR "If you're not using bundled LDAP schema (objectClass=openVPNUser)\n";
	print STDERR "you must define attribute mapping with configuration file.\n";
	print STDERR "\n";

	print STDERR "BATCH (DUMP CONFIGURATION) OPTIONS:\n";
	print STDERR "         --ccd-dir            OpenVPN client configuration directory (Default: ", dump_var($ccd_dir), ")\n";
	print STDERR "  -O     --set-option KEY=VAL Sets OpenVPN enviromental option.\n";
	print STDERR "                              See openvpn(8) under section \"Environmental Variables\"\n";
	print STDERR "                              for detailed name and value exaplanation.\n";
	print STDERR "\n";
	print STDERR "                              List of supported options: \n\n";
	foreach my $var (sort(@ovpn_env_vars)) {
		my $v = _getVar($var);
		$v = "" unless (defined $v);
		print STDERR "                              $var = $v\n";
	}
	print STDERR "\n";

	print STDERR "OTHER OPTIONS:\n";
	print STDERR "  -q     --quiet           Quiet execution in openvpn server call mode (Default: ", dump_var($quiet, 1), ")\n";
	print STDERR "  -V     --version         Prints script version and exits.\n";
	print STDERR "         --help            Prints this help message.\n";
}

sub _resolve {
	my @result = ();

	while (defined (my $host = shift(@_))) {
		next unless (length($host) > 0);

		my (undef, undef, undef, undef, @addrs) = gethostbyname($host);
		unless (@addrs) {
			return ();
		}
		map { $_ = inet_ntoa($_); } @addrs;

		msg_verb("LDAP CONNECT: Resolved addresses for host $host: ", join(", ", @addrs));
		push(@result, @addrs);
	}

	if ($randomize_host_connect_order) {
		msg_verb("LDAP CONNECT: Randomizing resolved addresses.");
		return shuffle(@result);
	} else {
		return @result;
	}
}

sub ldapConnect {
	my ($host) = @_;
	my $conn = undef;

	# resolve address
	my @ips = _resolve(split(/[\s;,]+/, $host));
	
	unless (@ips) {
		$Error = "No IP addresses were resolved from addresses: $host";
		return undef;
	}

	###############################################################
	# PHASE I: connect                                            #
	###############################################################
	msg_verb ("LDAP CONNECT: Connecting to LDAP server(s): ", join(", ", @ips) . "; TLS: " . (($tls) ? "yes" : "no"));
	$conn = Net::LDAP->new(
		\ @ips,
		port => $ldap_port,
		timeout => $ldap_timeout,
		version => $ldap_version,
		debug => $ldap_debug	
	);
	
	unless (defined $conn) {
		$Error = "Unable to connect to LDAP server(s): '" . join(", ", @ips) . "': $@";
		return undef;
	}

	###############################################################
	# PHASE II: start TLS                                         #
	###############################################################
	if ($tls) {
		msg_verb("LDAP CONNECT: Trying to start TLS session.");
		my $r = $conn->start_tls(
			verify => $tls_verify,
			sslversion => $tls_sslversion,
			ciphers => $tls_ciphers,
			clientcert => $tls_clientcert,
			clientkey => $tls_clientkey,
			capath => $tls_capath,
			cafile => $tls_cafile
		);
		if ($r->is_error()) {
			$Error = "Unable to start secure transport: LDAP error code " . $r->code() . ": " . $r->error();
			return undef;
		} else {
			msg_verb("LDAP CONNECT: TLS session successfuly established.");
		}
	}

	return $conn;
}

sub strip {
	my ($str) = @_;
	$str =~ s/^\s+//g;
	$str =~ s/\s+$//g;
	return $str;
}


sub getFilter {
	my $str = $search_filter;
	# rewrite search filter
	$str =~ s/%{([^}]+)}/_rewrite_var($1)/ge;
	return $str;
}

sub _rewrite_var {
	my ($var) = @_;
	my $val = _getVar($var);
	
	if (defined $val) {
		# escape value...
		$val =~ s/([\(\)\*\\\0])/\\$1/g;
	} else {
		$val = "*";
	}

	return $val;
}

sub _getVar {
	my ($name) = @_;
	return undef unless (defined $name);
	if (exists($ENV{$name}) && defined($ENV{$name})) {
		return $ENV{$name};
	}

	return undef;
}

sub ldapBind {
	my ($conn, $binddn, $password, $sasl_user, $sasl_mech) = @_;
	$sasl_mech = $bind_sasl_mech unless (defined $sasl_mech);

	unless (length($binddn) > 0) {
		$Error = "Unable to bind with empty bind DN.";
		return 0;
	}
	unless (length($password)) {
		msg_warn("Trying to bind with empty password.");
	}

	# simple bind or sasl bind?
	my $r = undef;

	#########################################################
	#                    SASL LDAP BIND                     #
	#########################################################
	if (defined $sasl_user && length($sasl_user) > 0) {
		msg_verb("Using SASL (mechanism $sasl_mech) LDAP bind method.");
		eval { require Authen::SASL; };
		
		if ($@) {
			$Error = "SASL authentication support is not available due to missing perl libraries.";
			return 0;
		}

		msg_debug("Binding as DN '$sasl_user' with password '$password'.");

		# create SASL object
		my $sasl = undef;
		eval {
			$sasl = Authen::SASL->new(
				mechanism => $bind_sasl_mech,
				callback => {
					user => $sasl_user,
					pass => $password
				}
			);
		};

		unless (defined $sasl) {
			$Error = "Unable to create SASL authentication object: $@";
			return 0;
		}

		# this is sooo stupid - sasl authzid must match $USER environment variable
		# (cyrus sasl requirement)
		my $user = $ENV{USER};
		$ENV{USER} = $sasl_user;
		
		if (! $tls && (lc($sasl_mech) eq 'plain' || lc($sasl_mech) eq 'login')) {
			msg_warn("You're bind LDAP server using unsecured network connection using insecure SASL authentication method! Password will be sent in cleartext!");
		}

		# try to bind
		eval {
			$r = $conn->bind(
				$bind_dn,
				sasl => $sasl
			);
		};
		
		# restore environment variable
		$ENV{USER} = $user;

	#########################################################
	#                   SIMPLE LDAP BIND                    #
	#########################################################
	} else {
		unless ($tls) {
			msg_warn("You're binding LDAP server using unsecured network connection! Password will be sent in cleartext!");
		}

		# try to bind
		$r = $conn->bind(
			$binddn,
			password => $password
		);
	}

	# check for injuries
	if ($r->is_error()) {
		$Error = "Error binding LDAP server: " . $r->error();
		return 0;
	} else {
		msg_debug("LDAP bind succeeded as '$binddn'.");
	}

	# return success
	return 1;
}

sub getEntries {
	my $conn = ldapConnect($ldap_server);
	unless ($conn) {
		msg_fatal("LDAP connection failed: $Error");
	}
	
	my $filter = getFilter();
	
	msg_verb("LDAP SEARCH: Search filter: '$filter'");
	
	my $r = $conn->search(
		base => $search_basedn,
		scope => $search_scope,
		deref => $search_deref,
		timelimit => $ldap_timeout,
		filter => $filter
	);
	
	if ($r->is_error()) {
		$Error = "Error performing LDAP search with filter '$filter' in search base '$search_basedn': " . $r->error();
		return undef;
	}
	
	# any entries found?
	if ($r->count() > 0) {
		msg_verb("LDAP SEARCH: Found " . $r->count() . " suitable LDAP entries.");
	} else {
		$Error = "LDAP SEARCH: No suitable LDAP entries found for LDAP search filter '$filter'.";
		msg_err($Error);
		return undef;	
	}

	return $r;
}

sub getFd {
	my ($file) = @_;
	my $fd = undef;
	$Error = "";
	$file = "-" unless (defined $file && length($file) > 0);
	
	if ($file eq '-') {
		$fd = IO::Handle->new();
		$fd->fdopen(fileno(STDOUT), 'w');
	} else {
		$fd = IO::File->new($file, 'w');
	}
	
	unless (defined $fd) {
		$Error = "Unable to open file '$file': $!";
	}

	return $fd;
}

sub tmp_filename {
	my $str = undef;
	do {
		$str = File::Spec->catfile(File::Spec->tmpdir(), $MYNAME . "-" . rand() . ".tmp"); 
	} while (! defined($str) && ! -e $str);

	return $str;
}

sub ldapEntry2File {
	my ($entry, $file) = @_;	
	my $fd = getFd($file);
	return 0 unless ($fd);

	unless (ref($entry) && $entry->isa("Net::LDAP::Entry")) {
		$Error = "Invalid entry object.";
		return 0;
	}
	
	print $fd "#\n";
	print $fd "# WHAT:	OpenVPN client configuration file\n";
	print $fd sprintf("# BY:	%s version %-.2f on %s\n", $MYNAME, $VERSION, strftime("%Y/%m/%d @ %H:%M:%S", localtime(time())));
	print $fd "# \n";
	print $fd "\n";
	print $fd "# META INFO: \n";
	print $fd "# \n";
	print $fd "# LDAP DN:		", $entry->dn(), "\n";
	print $fd "# LDAP search base:	", $search_basedn, "\n";
	print $fd "# LDAP search scope:	", $search_scope, "\n";
	print $fd "# LDAP deref:		", $search_deref, "\n";
	print $fd "# LDAP Filter:		", getFilter(), "\n";
	print $fd "#\n\n\n";
	
	# try to fetch all configuration parameters
	foreach my $ovpn_param (sort(keys(%{$schema_mapping}))) {
		# resolve LDAP object attribute name
		my $attr_name = undef;
		if (exists($schema_mapping->{$ovpn_param}) && defined($schema_mapping->{$ovpn_param})) {
			$attr_name = $schema_mapping->{$ovpn_param}
		}
		next unless (defined $attr_name);
		
		# skip processing if attribute does not exist in entry
		next unless ($entry->exists($attr_name));

		# fetch entry value
		my $value = $entry->get_value($attr_name, asref => 1);

		# resolve parameter type
		my $type = undef;
		if (exists($openvpn_config_types->{$ovpn_param})) {# && defined($openvpn_config_types->{$ovpn_param})) {
			$type = $openvpn_config_types->{$ovpn_param};
		}
		$type = $openvpn_config_type_default unless (defined $type);

		# decide how to write value && write it.
		my $write_str = "";
		if ($ovpn_param eq 'ifconfig-push') {
			my $val = strip(join("", @{$value}));
			# implement server local address expansion...
			my $local = "";
			my $remote = undef;

			# does backend describe full ifconfig-push?
			if ($val =~ m/^([^\s]+)\s+(.+)/) {
				$local = strip($1);
				$remote = strip($2);
			# nope. We need somehow to determine remote (openvpn server address)
			} else {
				$local = $val;

				my $l_ip = _getVar($openvpn_var_server_addr);
				my $l_mask = _getVar($openvpn_var_server_netmask);
				if ($l_ip) {
					$remote = $l_ip;
					$remote .= "-" . $l_mask if (defined $l_mask && length($l_mask));
				}
			}

			unless (defined $remote && length($remote) > 0) {
				$Error = "Remote addres is not defined. Set OpenVPN options ifconfig_pool_local_ip and ifconfig_pool_netmask using ovpn_option_safe() in configuration file or -O command line parameter and try again.";
				return 0;
			}

			$write_str = "ifconfig-push " . $local . " " . $remote;		
		} else {
			if ($type == CFG_BOOL) {
				my $str = lc(join("", @{$value}));
				if ($str eq 'true' || $str eq 'yes' || $str eq 'y' || $str eq '1') {
					$write_str = 'push "' . $ovpn_param . '"';
				}
			}
			elsif ($type == CFG_STR) {
				my $str = join(" ", @{$value});
				$write_str = 'push "' . $ovpn_param . " " . $str . '"';
			}
			elsif ($type == CFG_INT) {
				$write_str = 'push "' . $ovpn_param . " " . int(join("", @{$value})) . '"';
			}
			elsif ($type == CFG_STR_ARR) {
				foreach my $chunk (@{$value}) {
					my $str = strip($chunk);
					$write_str .= 'push "' . $ovpn_param . " " . $str . '"' . "\n";
				}
			}
		}
		
		# write the goddamn string...
		if (defined $write_str && length($write_str) > 0) {
			print $fd $write_str, "\n";
		}
	}

	print $fd "\n# EOF\n";

	# close file	
	unless ($fd->close()) {
		$Error = "Unable to close client configuration file: $!";
		return 0;
	}
	$fd = undef;

	return 1;
}

sub action_generic_run {
	my ($file) = @_;
	$file = "-" unless (defined $file);

	# first, our job is to determine
	# if we've been invoked by openvpn
	# server as client connect script, or via command line	
	my $type = _getVar("script_type");

	# dump all entries to some directory...
	if (! defined($type) || $type ne 'client-connect') {
		unless ($quiet) {
			msg_info();
			msg_info("$MYNAME is not invoked as --client-connect script, switching to configuration dump mode.");
			msg_info();
		}

		unless (_check_backup_dir()) {
			msg_fatal($Error);
		}

		# fetch all entries...
		my $r = getEntries();
		
		unless (defined $r) {
			msg_fatal($Error);
		}

		print STDERR "\n\n" unless ($quiet);
		# for each and every entry... write a file...
		while (defined (my $entry = $r->shift_entry())) {
			# determine entry x509 certificate common name
			my $x509_cn = undef;
			if ($entry->exists($openvpn_schema_x509cn)) {
				$x509_cn = $entry->get_value($openvpn_schema_x509cn);
			}
			unless (defined $x509_cn) {
				msg_warn("Entry ", $entry->dn(), " does not have attribute '$openvpn_schema_x509cn', skipping.");
				next;
			}

			# calculate filename
			my $f = File::Spec->catfile($ccd_dir, $x509_cn);
			my $tmp_fname= tmp_filename();

			# write entry to temporary file...
			unless (ldapEntry2File($entry, $tmp_fname)) {
				unlink($tmp_fname);
				msg_fatal("Unable to write LDAP entry: $Error");
			}
			
			# compute file digests (this is optional...)
			my $tmp_fname_digest = file_digest($tmp_fname);
			my $f_digest = file_digest($f);
			# same digests?
			if (defined $tmp_fname_digest && $f_digest && $tmp_fname_digest eq $f_digest) {
				msg_verb("Old client configuration file '$f' has the same data digest as new one, skipping overwrite.");
				unlink($tmp_fname);		
				next;
			}
			
			# check for previous existence...
			if (defined $backup_dir && length($backup_dir) > 0) {
				if (-f $f) {
					my $bck_f = File::Spec->catfile($backup_dir, basename($f) . ".backup." . strftime("%Y%m%d-%H%M%S", localtime(time())));
					unless (copy($f, $bck_f)) {
						msg_err("Unable to create backup $f -> $bck_f: $!");
						exit 1;
					}
				}
			}			
			
			# move it to correct location
			msg_info("Writing configuration file for CN=$x509_cn into '$f'.");
			unless (move($tmp_fname, $f)) {
				msg_err("Unable to move $tmp_fname -> $f: $!");
				unlink($tmp_fname);
				exit 1;
			}
		}
		
		# perform backup directory cleanup...
		_cleanup_backup_dir($backup_dir);

	# we're --client-connect script...
	} else {
		# silence script output
		$quiet = 1;

		my $common_name = _getVar("common_name");
		unless (defined $common_name && length($common_name) > 0) {
			msg_fatal("Undefined enviromental variable 'common_name'.");
		}
		unless (_check_ovpn_vars()) {
			msg_fatal("Undefined or missing OpenVPN server enviromental variables.");
		}

		# well... Let's search for suitable entry...
		my $r = getEntries();
		unless (defined $r) {
			msg_fatal($r);
		}

		# fetch only first entry and write it to file
		my $entry = $r->shift_entry();
		unless (ldapEntry2File($entry, $file)) {
			msg_err("Unable to write LDAP entry: $Error");
			unlink($file);
			exit 1;
		}
	}
	
	return 1;
}

sub _cleanup_backup_dir {
	my ($dir, $older_than) = @_;
	$older_than = $backup_dir_purge_older_than;
	return 1 if ($older_than < 1);
	return 0 unless (defined $dir);
	return 0 unless (-d $dir && -w $dir);
	
	# open dir
	my $dirh = undef;
	return unless (opendir($dirh, $dir));
	
	# current time
	my $min_time = time() - $older_than;

	# read directory...
	while (defined (my $entry = readdir($dirh))) {
		# skip current and parent directory
		next if ($entry eq '.' || $entry eq '..');
		my $f = File::Spec->catfile($dir, $entry);
		next if (-l $f);
		next unless (-f $f);
		
		# check mtime
		my @tmp = stat($f);
		next unless (@tmp);
		if ($tmp[9] < $min_time) {
			msg_verb("Removing too old entry from backup dir: $entry");
			unlink($f);
		}
	}
	

}

sub _check_backup_dir {
	# return success in case of undefined backup dir
	return 1 unless (defined $backup_dir && length($backup_dir) > 0);
	my $result = 0;
	
	if (! -e $backup_dir) {
		$Error = "directory does not exist.";
	}
	elsif (! -d $backup_dir) {
		$Error = "not a directory.";
	}
	elsif (! -w $backup_dir) {
		$Error = "not a writeable directory.";
	}
	elsif (realpath($backup_dir) eq realpath($ccd_dir)) {
		$Error = "backup_dir is the same location as ccd_dir.";
	} else {
		$result = 1;
	}
	
	unless ($result) {
		$Error = "Invalid backup directory '$backup_dir': " . $Error;
	}

	return $result;
}

sub _check_ovpn_vars {
	my $r = 1;
	foreach my $var (@ovpn_env_vars) {
		my $v = _getVar($var);
		unless (defined $v) {
			msg_warn("OpenVPN server Environmental variable $var is not defined.");
			$r = 0;
		}
	}

	return $r;
}

sub ovpn_option_safe {
	my @x = @_;
	my ($key, $value) = (undef, undef);
	$key = shift();
	my @tmp = split(/=/, $key);
	$key = shift(@tmp);

	return 1 if (exists($ENV{$key}));
	return ovpn_option(@x);
}

sub ovpn_option {
	my @x = @_;
	my ($key, $value) = (undef, undef);
	$key = shift();
	my @tmp = split(/=/, $key);
	$key = shift(@tmp);
	
	if (@tmp) {
		$value = join("=", @tmp);
	} else {
		$value = shift();
	}

	unless (defined $key && defined $value) {
		msg_fatal("Invalid ovpn_option '", join("", @x), "': Missing key and/or value.");
	}
	
	# set the goddamn option...
	$ENV{$key} = $value;
	return 1;
}

#############################################################
#                           MAIN                            #
#############################################################

# initialize script
script_init();

# load default config files...
unless (config_load_default()) {
	msg_fatal("Error loading default configuration file: $Error");
}

# parse command line
Getopt::Long::Configure("bundling");
my $r = GetOptions(
	'c|config=s' => sub {
		unless (config_load($_[1])) {
			msg_fatal($Error);
		}
	},
	'd|default-config' => sub {
		config_default();
		exit 0
	},

	'h|ldap-server=s' => sub {
		if (length($ldap_server) < 1 || $ldap_server eq 'localhost') {
			$ldap_server = $_[1];
		} else {
			$ldap_server .= ", " . $_[1];
		} 
	},
	'P|ldap-port=i' => \ $ldap_port,
	'randomize-conn!' => \ $randomize_host_connect_order,
	'ldap-version=i' => \ $ldap_version,
	'ldap-timeout=i' => \ $ldap_timeout,
	'ldap-debug!' => \ $ldap_debug,
	'u|bind-dn=s' => \ $bind_dn,
	'p|bind-pw=s' => \ $bind_pw,
	'bind-sasl!' => \ $bind_sasl,
	'bind-sasl-authzid=s' => \ $bind_sasl_authzid,
	'bind-sasl-mech=s' => \ $bind_sasl_mech,
	'b|search-basedn=s' => \ $search_basedn,
	'f|search-filter=s' => \ $search_filter,
	'search-scope=s' => \ $search_scope,
	'search-deref=s' => \ $search_deref,
	't|tls!' => \ $tls,
	'tls-verify=s' => \ $tls_verify,
	'tls-sslversion=s' => \ $tls_sslversion,
	'tls-ciphers=s' => \ $tls_ciphers,
	'tls-clientcert=s' => \ $tls_clientcert,
	'tls-clientkey=s' => \ $tls_clientkey,
	'tls-cafile=s' => \ $tls_cafile,
	'tls-capath=s' => \ $tls_capath,
	'ccd-dir=s' => \ $ccd_dir,
	'O|set-option=s' => sub {
		my @tmp = split(/=/, $_[1]);
		my $key = shift(@tmp);
		my $val = join("=", @tmp);
		$ENV{$key} = $val;
	},
	'q|quiet!' => \ $quiet,
	'V|version' => sub {
		printf("%s %-.2f\n", $MYNAME, $VERSION);
		exit 0;
	},
	'help' => sub {
		printhelp();
		exit 0;
	}
);

unless ($r) {
	msg_fatal("Invalid command line options. Run $MYNAME --help for instructions.");
}

# run the bastard...
exit (! action_generic_run(@ARGV));

# EOF