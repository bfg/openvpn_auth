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

# $Id:LDAP.pm 188 2007-03-29 11:39:03Z bfg $
# $LastChangedRevision:188 $
# $LastChangedBy:bfg $
# $LastChangedDate:2007-03-29 13:39:03 +0200 (Thu, 29 Mar 2007) $

package Net::OpenVPN::Auth::LDAP;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Socket;
use Net::LDAP;
use Log::Log4perl;
use List::Util qw(shuffle);

# my modules
use Net::OpenVPN::PasswordValidator;

=head1 NAME LDAP

LDAP directory service authentication backend module.

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<auth_method> (string, "search") Specifies LDAP authentication method. Valid values: B<search>, B<pass_attr>

SEARCH method

Connect to LDAP server (anonymously), search for user's distiguished name (DN), then reconnect to LDAP server and try to bind (login) as found DN.
B<This is preferred method for LDAP authentication.>

PASS_ATTR method

Connect to LDAP server using DN specified by B<bind_dn> property, search for user's object in directory, read
password attribute specified by B<password_attribute> property and evaluate password hash, depending on B<password_default_hash>
property. 

B<password_attribute> (string, "userPassword") LDAP object password attribute. This option is only used when B<auth_method> property is set to B<pass_attr>,
otherwise is completely ignored, becouse password validation is done by LDAP server.

B<password_default_hash> (string, "PLAIN") Normally, LDAP objects have stored password in {PASSWORD_HASH_TYPE}HASH_TEXT format. This property specifies
password hashing algorithm when retrieved password doesn't have {PASSWORD_HASH_TYPE} prefix. If you have properly configured LDAP server, you don't need
to set this property. This property is used only, when B<auth_method> is set to B<pass_attr>, otherwise is completely ignored. Supported password hashes:
B<PLAIN, CRYPTMD5, MD5, NTLM, SHA1, SSHA>

B<host> (string, "127.0.0.1") LDAP server hostname or ip address. If you want to specifiy multiple ldap servers, you can separate them using comma (,) or
semicolon (;) character. B<Example>: ldap1.example.org, ldap2.example.org; ldap3.example.org

B<randomize_host_connect_order> (boolean, 1) When you specify more than one host in B<host> or when dns record specified in B<host> configuration property
specified is round-robin record and when this property is turned on (default) 
connection will be made to random resolved ldap server. This option provides load balancing. However, when this option is turned off,
connection will be first tried to first specified host, if it fails, then the next specified host will be tried.

B<persistent_connection> (boolean, 0) If set to value of 1, ldap connection will not be destroyed after each authentication request. Setting this to 1
can lead to better authentication performance, but it can lead to unpredictable results in case of ldap server restart.

B<port> (integer, 389) LDAP server port.

B<ldap_version> (integer, 3) LDAP protocol version. Unless you really know, what you're doing, you should leave it at it's default.

B<tls> (boolean, 0) If your LDAP server supports SSL or TLS B<it is strongly recommended, that you enable this option>. When enabled, all 
transmitted data and passwords are encrypted. This option requires IO::Socket::SSL perl module.

B<tls_verify> (string, "none") See IO::Socket:SSL perldoc for more info.

B<tls_sslversion> (string, "tlsv1") See IO::Socket:SSL perldoc for more info.

B<tls_ciphers> (string, "HIGH") See IO::Socket:SSL perldoc for more info.

B<tls_clientcert> (string, "") See IO::Socket:SSL perldoc for more info.

B<tls_clientkey> (string, "") See IO::Socket:SSL perldoc for more info.

B<tls_capath> (string, "") See IO::Socket:SSL perldoc for more info.

B<tls_cafile> (string, "") See IO::Socket:SSL perldoc for more info.

B<bind_dn> (string, "") Bind with the specified distinguished name (DN) when searching for user's object. If this property is empty, module will try
to bind anonymously, which is completely ok in most setups with B<search> authentication method. If you would like to use B<pass_attr> authentication
method, then you need to specify DN, which has permission to read LDAP object password (not recommended).  

B<bind_sasl> (boolean, 0) Enables SASL to bind LDAP directory. Requiures Authen::SASL module.

B<bind_sasl_authzid> (string, "") SASL authentication id.

B<bind_sasl_mech> (string, "PLAIN") SASL bind mechanism.

B<bind_pw> (string, "") DN password

B<search_basedn> (string, "") LDAP search base

B<search_filter> (string, "(objectClass=*)") LDAP search filter. You can use the following magic cookies in it: B<%{username}, %{password}, %{host}, %{cn}, %{port}>

B<search_scope> (string, "sub") LDAP search scope. Valid values: B<sub, one, base>

B<search_deref> (string, "none") Valid values: B<never, search, find, always>

B<debug> (boolean, 0) heavy LDAP operation debug

B<timeout> (integer, 2) LDAP connection socket operation timeout in seconds

=cut
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = $class->SUPER::new(@_);

	##################################################
	#               PUBLIC VARS                      #
	##################################################

	##################################################
	#              PRIVATE VARS                      #
	##################################################
	$self->{_name} = "LDAP";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	# initialize object
	$self->clearParams();
	$self->setParams(@_);
	$self->_init();

	return $self;
}

sub clearParams {
	my ($self) = @_;
	$self->SUPER::clearParams();
	
	# auth method: search for directory
	# entry and try to bind as entry if found
	# or try to read password from entry
	#
	# can be:
	#	"search" :: search for user's dn, try to bind as found dn
	#   "pass_attr"  :: search for user's dn, try to read password attribute, try to verify password hash  
	$self->{auth_method} = "search";
	
	$self->{persistent_connection} = 0;		# connect/disconnect after every authenticate()
	$self->{randomize_host_connect_order} = 1;		# use random resolved host address for connection
	
	# entry password attribute
	$self->{password_attribute} = "userPassword";
	$self->{password_default_hash} = "PLAIN";

	$self->{host} = "127.0.0.1";
	$self->{port} = 389;
	$self->{ldap_version} = 3;
	$self->{tls} = 0;

	$self->{tls_verify} = "none";		# See:
	$self->{tls_sslversion} = "tlsv1";	#     perldoc IO::Socket::SSL
	$self->{tls_ciphers} = "HIGH";		#     perldoc Net::LDAP
	$self->{tls_clientcert} = "";		# for more info regarding these
	$self->{tls_clientkey} = "";			# variables
	$self->{tls_capath} = "";			#
	$self->{tls_cafile} = "";			#

	$self->{bind_dn} = "";				# bind DN
	$self->{bind_sasl} = 0;				# use sasl auth?
	$self->{bind_sasl_authzid} = "";	# sasl authorization id
	$self->{bind_sasl_mech} = "PLAIN";	# sasl auth mechanism
	$self->{bind_pw} = "";				# bind password

	$self->{search_basedn} = "";			# search base
	$self->{search_filter} = "(objectClass=*)";		# ldap search filter
	$self->{search_scope} = "sub";		# search scope (sub, one, none)
	$self->{search_deref} = "none";		# deref results?

	$self->{debug} = 0;
	$self->{timeout} = 2;

	$self->{_conn} = undef;
	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));
	$self->{error} = "";
	my $r = 0;
	
	# what kind of authentication should we perform?
	if ($self->{auth_method} eq 'search') {
		$r = $self->_authenticateSearch($struct);	
	}
	elsif ($self->{auth_method} eq 'pass_attr') {
		$r = $self->_authenticatePwAttr($struct);		
	} else {
		$self->{error} = "Invalid LDAP password verification method: '" . $self->{auth_method} . "'.";
	}

	# disconnect if necessary
	$self->_disconnect() unless ($self->{persistent_connection});

	return $r;
}

sub _init {
	my ($self) = @_;
	
	# check for SASL library support
	eval { require Authen::SASL; };
	$self->{_has_authen_sasl} = ($@) ? 0 : 1;
	$self->{_log}->debug("Cyrus SASL support available: " . ($self->{_has_authen_sasl}) ? "yes." : "no.");

	# create password validator object
	$self->{_validator} = Net::OpenVPN::PasswordValidator->new();
	# $self->{_log}->debug("Module supported password hashing algorithms: ", join(", ", sort(@unavail, @avail)));
	# $self->{_log}->debug("Disabled password hashing algorithms (required perl modules are unavailable): ", join(", ", sort(@unavail)));
	# $self->{_log}->info("Enabled password hashing algorithms: ", join(", ", sort(@avail)));

	return 1;
}

sub _authenticatePwAttr {
	my ($self, $struct) = @_;
	return 0 unless ($self->_connect());
	
	$self->{_log}->debug("Performing password-attribute fetch authentication.");

	# stupid admin check...
	unless ($self->{tls}) {
		$self->{_log}->warn("Password attribute fetch and evaluate type of authentication used over unsecured connection!");
		$self->{_log}->warn("Do you know what are you doing?!");
		unless ($self->{bind_sasl}) {
			$self->{_log}->warn("You are binding LDAP server WITHOUT using strong SASL authentication, therefore you're transmitting DN/password pair over INSECURE connection!!!");
			$self->{_log}->warn("THIS IS INSANE!");
		}
		$self->{_log}->warn("You're transmitting user passwords over network in cleartext!!!");
		$self->{_log}->warn("THIS IS INSANE!");
		$self->{_log}->warn("Doing authentication this way is stupid, therefore i will delay authentication for 3 seconds.");
		sleep(3);
	}

	# well... we must find user's entry...
	my $filter = $self->_getFilter($struct);
	return 0 unless (defined $filter);

	my $r = $self->_ldapSearch($filter);
	return 0 unless (defined $r);

	# get entry...
	my $e = $r->shift_entry();

	# just in case...
	my $dn = $e->dn();
	unless (defined $dn && length($dn) > 0) {
		$self->{error} = "Found LDAP entry with invalid DN. How can that be?!";
		$self->{_log}->error($self->{error});
		return 0;
	}

	# check for password attribute
	unless ($e->exists($self->{password_attribute})) {
		$self->{error} = "Fetched entry with DN '$dn' doesn't contain defined password attribute '" . $self->{password_attribute} . "'.";
		return 0;
	}
	
	# get password "hash"
	my $pwhash = $e->get_value($self->{password_attribute});
	
	unless (length($pwhash)) {
		$self->{_log}->warn("LDAP entry DN '$dn' has empty password attribute!");
	}

	$self->{_log}->debug("Fetched password for entry DN '$dn': '$pwhash'.");

	# parse password hash
	my $pwtype = undef;
	if ($pwhash =~ m/^{(.+)}(.+)$/) {
		$pwtype = uc($1);
		$pwhash = $2;
	} else {
		$self->{_log}->warn("DN '$dn': Fetched password is not in standard '{TYPE}hash' format. Applying default password format '" . $self->{password_default_hash} . "'.");
		$pwtype = $self->{password_default_hash};
	}
	
	if ($pwhash =~ m/^\$1\$/) {
		$pwtype = "CRYPTMD5";
	}
	elsif ($pwhash =~ m/^\$2\$/) {
		$pwtype = "CRYPTBLOWFISH";
	}
	elsif ($pwtype eq 'MD5') {
		$pwtype = "MD5";
	}
	elsif ($pwtype eq 'SHA') {
		$pwtype = "SHA1"
	}
	elsif ($pwtype eq 'SMD5') {
		
	}
	elsif ($pwtype eq 'SSHA') {
	
	}

	# check password hash
	$self->{_log}->debug("Validating password hash using '$pwtype' hashing algorithm.");
	my $result = $self->{_validator}->validatePassword($pwhash, $struct->{password}, $pwtype);
	unless ($result) {
		$self->{error} = $self->{_validator}->getError();
	}

	return $result;
}

sub _authenticateSearch {
	my ($self, $struct) = @_;
	return 0 unless ($self->_connect());

	$self->{_log}->debug("Performing DN-search-bind authentication.");

	# prepare search filter
	my $filter = $self->_getFilter($struct);
	return 0 unless (defined $filter);

	# run search
	my $r = $self->_ldapSearch($filter);

	# check
	unless (defined $r) {
		$self->{error} = "Invalid username.";
		return 0;
	}

	# get dn
	my $dn = $r->shift_entry()->dn();

	# just in case...
	unless (defined $dn && length($dn) > 0) {
		$self->{error} = "Found LDAP entry with invalid DN. How can that be?!";
		$self->{_log}->error($self->{error});
		return 0;
	}

	# ok, create new ldap connection...
	my $conn = $self->_ldapConnect($self->{host});
	return 0 unless (defined $conn);

	# ... and finally... try to bind directory
	return $self->_ldapBind(
		$conn,
		$dn,
		$struct->{password}
	);
}

sub _getFilter {
	my ($self, $struct) = @_;

	# don't cry about non-initialized strings...
	no warnings;
	
	# filter integrity check... 
	# escape weird characters in structure...
	foreach my $key (keys %{$struct}) {
		my $old = $struct->{$key};
		$struct->{$key} =~ s/([\(\)\*\\\0])/\\$1/g;
		if ($old ne $struct->{$key} && $key ne 'password') {
			$self->{_log}->warn("Authentication structure contains key '$key' with suspicious characters. String '$old' rewritten to '$struct->{$key}'.");
		}
	}

	# rewrite filter
	my $str = $self->{search_filter};
	$str =~ s/%\{username\}/$struct->{username}/g;
	$str =~ s/%\{password\}/$struct->{password}/g;
	$str =~ s/%\{host\}/$struct->{host}/g;
	$str =~ s/%\{cn\}/$struct->{cn}/g;
	$str =~ s/%\{port\}/$struct->{port}/g;

	return $str;
}

sub _ldapSearch {
	my ($self, $filter) = @_;
	return undef unless ($self->_connect());
	$self->{_log}->debug("LDAP search filter: $filter");

	my $r = $self->{_conn}->search(
		base => $self->{search_basedn},
		scope => $self->{search_scope},
		deref => $self->{search_deref},
		timelimit => $self->{timeout},
		filter => $filter,
	);
	
	if ($r->is_error()) {
		$self->{error} = "Error performing LDAP search with filter '$filter' in search base '$self->{search_basedn}': " . $r->error();
		$self->{_log}->error($self->{error});
		return undef;
	}
	
	# any entries found?
	unless ($r->count() > 0) {
		$self->{error} = "No suitable LDAP entries found for LDAP search filter '$filter'.";
		$self->{_log}->warn($self->{error});
		return undef;
	}

	# return search result
	return $r;
}


# returns (TLS secured?) ldap connection on success
# otherwise undef. Ldap connection is not bound.
sub _ldapConnect {
	my ($self, $host) = @_;
	my $conn = undef;

	# resolve address
	my @ips = $self->_resolve(split(/[\s;,]+/, $host));
	return undef unless (@ips);

	###############################################################
	# PHASE I: connect                                            #
	###############################################################
	$self->{_log}->debug("Connecting to LDAP server(s): ", join(", ", @ips) . "; TLS: " . (($self->{tls}) ? "yes" : "no"));
	$conn = Net::LDAP->new(
		\ @ips,
		port => $self->{port},
		timeout => $self->{timeout},
		version => $self->{ldap_version},
		debug => $self->{debug}	
	);
	
	unless (defined $conn) {
		$self->{error} = "Unable to connect to LDAP server '" . $self->{host} . "': $@";
		$self->{_log}->error($self->{error});
		return undef;
	}

	###############################################################
	# PHASE II: start TLS                                         #
	###############################################################
	if ($self->{tls}) {
		$self->{_log}->debug("Trying to start TLS session.");
		my $r = $conn->start_tls(
			verify => $self->{tls_verify},
			sslversion => $self->{tls_sslversion},
			ciphers => $self->{tls_ciphers},
			clientcert => $self->{tls_clientcert},
			clientkey => $self->{tls_clientkey},
			capath => $self->{tls_capath},
			cafile => $self->{tls_cafile}
		);
		if ($r->is_error()) {
			$self->{error} = "Unable to start secure transport: LDAP error code " . $r->code() . ": " . $r->error();
			$self->{_log}->error($self->{error});
			return undef;
		} else {
			$self->{_log}->debug("TLS session successfuly established.");
		}
	}

	return $conn;
}

sub _ldapBind {
	my ($self, $conn, $binddn, $password, $sasl_user, $sasl_mech) = @_;
	$sasl_mech = $self->{bind_sasl_mech} unless (defined $sasl_mech);

	unless (length($binddn) > 0) {
		$self->{error} = "Unable to bind with empty bind DN.";
		return 0;
	}
	unless (length($password)) {
		$self->{_log}->warn("Trying to bind with empty password.");
	}
	
	# simple bind or sasl bind?
	my $r = undef;

	#########################################################
	#                    SASL LDAP BIND                     #
	#########################################################
	if (defined $sasl_user && length($sasl_user) > 0) {
		$self->{_log}->debug("Using SASL (mechanism $sasl_mech) LDAP bind method.");
		unless ($self->{_has_authen_sasl}) {
			$self->{error} = "SASL authentication support is not available due to missing perl libraries.";
			$self->{_log}->error($self->{error});
			return 0;
		}

		$self->{_log}->debug("Binding as DN '$sasl_user' with password '$password'.");
		
		# create SASL object
		my $sasl = undef;
		eval {
			$sasl = Authen::SASL->new(
				mechanism => $self->$sasl_mech,
				callback => {
					user => $sasl_user,
					pass => $password
				}
			);
		};

		unless (defined $sasl) {
			$self->{error} = "Unable to create SASL authentication object: $@";
			return 0;
		}

		# this is sooo stupid - sasl authzid must match $USER environment variable
		# (cyrus sasl requirement)
		my $user = $ENV{USER};
		$ENV{USER} = $sasl_user;
		
		if (! $self->{tls} && (lc($sasl_mech) eq 'plain' || lc($sasl_mech) eq 'login')) {
			$self->{_log}->warn("You're bind LDAP server using unsecured network connection using insecure SASL authentication method! Password will be sent in cleartext!");
		}

		# try to bind
		eval {
			$r = $conn->bind(
				$self->{bind_dn},
				sasl => $sasl
			);
		};
		
		# restore environment variable
		$ENV{USER} = $user;

	#########################################################
	#                   SIMPLE LDAP BIND                    #
	#########################################################
	} else {
		$self->{_log}->debug("Using simple LDAP bind method.");
		$self->{_log}->debug("Binding as DN '$binddn' with password '$password'.");

		unless ($self->{tls}) {
			$self->{_log}->warn("You're bind LDAP server using unsecured network connection! Password will be sent in cleartext!");
		}

		# try to bind
		$r = $conn->bind(
			$binddn,
			password => $password
		);
	}

	# check for injuries
	if ($r->is_error()) {
		$self->{error} = "Error binding LDAP server: " . $r->error();
		$self->{_log}->debug($self->{error});
		return 0;
	} else {
		$self->{_log}->debug("LDAP bind succeeded as '$binddn'.");
	}

	# return success
	return 1;
}

sub _connect {
	my ($self) = @_;

	# check for cached connection
	if ($self->{persistent_connection} && defined $self->{_conn}) {
		return 1;
	} else {
		$self->{_conn} = undef;
	}

	my $result = 0;
	$self->{error} = "";

	###############################################################
	# PHASE I: connect                                            #
	###############################################################
	$self->{_conn} = $self->_ldapConnect($self->{host});
	unless (defined $self->{_conn}) {
		$self->{error} = "Unable to connect to LDAP server '" . $self->{host} . "': $@";
		goto outta_connect;
	}
	###############################################################
	# PHASE II: LDAP bind                                         #
	###############################################################
	if (length($self->{bind_dn}) > 0) {
		my $r = $self->_ldapBind(
			$self->{_conn},
			$self->{bind_dn},
			$self->{bind_pw},
			$self->{bind_sasl_authzid},
			$self->{bind_sasl_mech},
		);

		goto outta_connect unless ($r); 
	}
	
	$result = 1;

	outta_connect:
	unless ($result) {
		$self->{_log}->error($self->{error});
		$self->{_conn} = undef;
	}

	return $result;
}

# disconnects from LDAP server
sub _disconnect {
	my ($self) = @_;
	if (defined $self->{_conn}) {
		$self->{_conn}->disconnect();
		$self->{_conn} = undef;
	}

	return 1;
}

# resolves hostname to list of ip addresses
sub _resolve {
	my $self = shift;
	my @result = ();
	
	while (defined (my $host = shift(@_))) {
		next unless (length($host) > 0);

		$self->{_log}->debug("Resolving address '$host'.");
		my (undef, undef, undef, undef, @addrs) = gethostbyname($host);
		unless (@addrs) {
			$self->{error} = "Unable to resolve '$host'.";
			$self->{_log}->fatal($self->{error});
			return ();
		}
		map { $_ = inet_ntoa($_); } @addrs;

		if ($self->{_log}->is_debug()) {
			$self->{_log}->debug("Resolved addresses: ", join(", ", @addrs));
		}

		push(@result, @addrs);
	}

	if ($self->{randomize_host_connect_order}) {
		return shuffle(@result);
	} else {
		return @result;
	}
}

# object destructor...
sub DESTROY {
	my ($self) = @_;
	return $self->_disconnect();
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<Net::LDAP>
L<IO::Socket::SSL>
L<Net::SSLeay>

=cut

1;