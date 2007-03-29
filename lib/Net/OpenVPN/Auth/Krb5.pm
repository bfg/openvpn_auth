# Copyright (c) 2006, Branko F. Gracnar
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
package Net::OpenVPN::Auth::Krb5;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Authen::Krb5::Simple;
use Log::Log4perl;

=head1 NAME Krb5

KerberosV authentication module. Requires already configured kerberos client (check if kinit(1) works) and installed
Authen::Krb5::Simple perl module.

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<realm> (string, "EXAMPLE.COM") KerberosV realm name. If username is in user@realm form, then realm is extracted from username.

=cut
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = $class->SUPER::new(@_);

	##################################################
	#               PUBLIC VARS                      #
	##################################################
	$self->{realm} = "EXAMPLE.COM";

	##################################################
	#              PRIVATE VARS                      #
	##################################################
	$self->{_name} = "Krb5";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);
	
	# initialize object
	$self->clearParams();

	return $self;
}

sub clearParams {
	my ($self) = @_;
	$self->SUPER::clearParams();
	$self->{realm} = "EXAMPLE.COM";
	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));	
	my $r = 0;
	
	# check if username contains realm
	my $realm = $self->{realm};
	my $user = $struct->{username};

	if ($struct->{username} =~ m/^(.+)@(.+)$/) {
		my $old_user = $user;
		my $old_realm = $realm;
		$user = $1;
		$realm = $2;
		$self->{_log}->warn("Rewriting username '$old_user' to '$user' and changing realm from '$old_realm' to '$realm'");
	}

	# initialize kerberos object
	my $krb = Authen::Krb5::Simple->new();
	$krb->realm($realm);
	
	$self->{_log}->debug("Trying to obtain kerberosV ticket as principal $user@$realm with password '" . $struct->{password} . "'.");
	# perform authentication
	eval {
		$r = $krb->authenticate($user, $struct->{password});
	};

	if ($@) {
		$self->{error} = "Kerberos authentication failed: $@\n";
		$self->{_log}->error($self->{error});
		$r = 0;
	}
	elsif (! $r) {
		$self->{error} = "Kerberos error " . $krb->errcode() . ": " . $krb->errstr();
		$self->{_log}->error($self->{error});
	}

	return $r;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<Authen::Krb5::Simple>

=cut

1;