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

# $Id:Radius.pm 188 2007-03-29 11:39:03Z bfg $
# $LastChangedRevision:188 $
# $LastChangedBy:bfg $
# $LastChangedDate:2007-03-29 13:39:03 +0200 (Thu, 29 Mar 2007) $

package Net::OpenVPN::Auth::Radius;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use Log::Log4perl;
use Authen::Radius;

=head1 NAME Radius

Radius authentication backend

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<host> (string, "localhost") radius server host

B<service> (string, "") radius service

B<secret> (string, "") radius secret

B<use_nas_ipaddr> (boolean, 0) Set authentication client's remote ip address as NAS IP?

B<timeout> (integer, 2) timeout for socket operations

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
	$self->{_name} = "Radius";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	$self->clearParams();
	$self->setParams(@_);

	return $self;
}

sub clearParams {
	my $self = shift;
	$self->SUPER::clearParams();
	
	$self->{host} = "localhost";
	$self->{service} = "radius";
	$self->{secret} = "";
	$self->{use_nas_ipaddr} = 0;
	$self->{timeout} = 2;

	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	return 0 unless ($self->validateParamsStruct($struct));
	$self->{_log}->debug("Creating radius auth object: host => '$self->{host}', secret => '$self->{secret}', service => '$self->{service}', timeout => $self->{timeout}.");
	my $radius = Authen::Radius->new(
		Host => $self->{host},
		Secret => $self->{secret},
		Service => $self->{service},
		Timeout => $self->{timeout},
		Debug => ($self->{_log}->is_debug() ? 1 : 0)
	);

	# validate password
	my $ip = ($self->{use_nas_ipaddr}) ? $struct->{untrusted_ip} : "127.0.0.1";
	$self->{_log}->debug("Performing Radius auth with NAS ip $ip");
	my $r = $radius->check_pwd(
		$struct->{username},
		$struct->{password},
		$ip
	);
	
	unless ($r) {
		$self->{error} = "Radius error: " . $radius->strerror();
		$self->{_log}->error($self->{error});
		return 0;
	}
	
	return $r;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<Authen::Radius>

=cut

# This line is mandatory...
1;