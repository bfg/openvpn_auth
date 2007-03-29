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
#

# $Id$
# $LastChangedRevision$
# $LastChangedBy$
# $LastChangedDate$

package Net::OpenVPN::AuthChain;

use strict;
use warnings;

use Log::Log4perl;

##################################################
#             OBJECT CONSTRUCTOR                 #
##################################################

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = {};

	##################################################
	#               PUBLIC VARS                      #
	##################################################
	$self->{error} = "";

	##################################################
	#              PRIVATE VARS                      #
	##################################################
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	$self->clearParams();
	$self->setParams(@_);

	return $self;
}

##################################################
#              PUBLIC  METHODS                   #
##################################################

sub clearParams {
	my $self = shift;
	@{$self->{_chain}} = qw();		# authentication module names
	$self->{_mods} = {};			# authentication module objects

	return 1;	
}

sub setParams {
	my $self = shift;
	$self->{error} = "";
	while (@_) {
		my $key = shift;
		my $value = shift;
		next if ($key =~ m/^_/ || $key eq 'error');
		$self->{$key} = $value;
	}
	
	return 1;
}

sub isValidChain {
	my ($self) = @_;
	my $res = 0;
	if (ref($self->{_chain}) ne 'ARRAY') {
		$self->{error} = "Chain is not array reference";
	}
	else {
		$res = 1;
	}
	return $res;
}

sub getError {
	my ($self) = @_;
	return $self->{error};
}

sub shiftModule {
	my ($self) = @_;
	my $obj = undef;
	my $name = shift(@{$self->{_chain}});

	if (exists($self->{_mods}->{$name})) {
		$obj = $self->{_mods}->{$name};
		delete($self->{_mods}->{$name});
	} else {
		$self->{error} = "There are no modules left.";
	}

	return $obj;
}

sub unshiftModule {
	my ($self, $name, $obj) = @_;
	return 0 unless ($self->checkModule($name, $obj));
	$obj->setName($name);
	$self->{_mods}->{$name} = $obj;
	unshift(@{$self->{_chain}}, $name);
	return 1;
}

sub pushModule {
	my ($self, $obj, $name) = @_;
	return 0 unless ($self->checkModule($obj));
	$self->{_mods}->{$obj->getName()} = $obj;
	push(@{$self->{_chain}}, $obj->getName());
	return 1;
}

sub popModule {
	my ($self) = @_;
	my $obj = undef;
	my $name = pop(@{$self->{_chain}});
	if (exists($self->{_mods}->{$name})) {
		$obj = $self->{_mods}->{$name};
		delete($self->{_mods}->{$name});
	} else {
		$self->{error} = "There are no modules left.";
	}
	return $obj;
}

sub checkModule {
	my ($self, $obj) = @_;
	my $result = 0;
	if (! defined $obj) {
		$self->{error} = "Undefined module object.";
	}
	elsif (! $obj->isa("Net::OpenVPN::Auth")) {
		$self->{error} = "Invalid authentication module object.";
	}
	else {
		$result = 1;
	}

	return $result;
}

sub clearModules {
	my ($self) = @_;
	@{$self->{_chain}} = ();
	$self->{_mods} = {};
	return 1;
}

sub getChain {
	my ($self, $objs) = @_;
	$objs = 0 unless (defined $objs);
	my @res;
	
	if ($objs) {
		foreach my $name (@{$self->{_chain}}) {
			push(@res, $self->{_mods}->{$name})
		}
	} else {
		@res = @{$self->{_chain}};
	}

	return @res;
}


sub getNumModules {
	my ($self) = @_;
	return ($#{$self->{_chain}} + 1);
}

sub getModuleIndex {
	my ($self, $name) = @_;
	my $i = 0;
	foreach my $n (@{$self->{_chain}}) {
		return $i if ($n eq $name);
		$i++;
	}

	return -1;
}

sub authenticate {
	my ($self, $struct) = @_;
	$self->{_log}->debug("Startup.");

	my $i = 0;
	my $num = $#{$self->{_chain}} + 1;
	foreach my $name (@{$self->{_chain}}) {
		$i++;
		$self->{_log}->debug("Checking module '$name'.");
		unless (exists($self->{_mods}->{$name})) {
			$self->{error} = "Invalid module name. This should never happen.";
			return 0;
		}
		my $r = $self->{_mods}->{$name}->isRequired();
		my $s = $self->{_mods}->{$name}->isSufficient();
		$self->{_log}->debug("Module '$name' properties: is_sufficiend: $s; is_required: $r.");

		# required module cannot be sufficient
		$s = 0 if ($r);

		# perform authentication
		my $auth_res = $self->{_mods}->{$name}->authenticate($struct);
		
		$self->{_log}->debug("Module '$name' authentication result: $auth_res");

		if ($auth_res) {
			if ($s) {
				$self->{_log}->debug("Module '$name' is sufficient and returned successfull authentication result. Assuming that global authentication succeeded, returning success.");
				return 1;
			}
			elsif ($i >= $num) {
				$self->{_log}->debug("Module '$name' is marked as required, returned successfull authentication response and is last module in authentication chain. Assuming that global authentication succeeded, returning success.");
				return 1;				
			}
		}

		if ($r && ! $auth_res) {
			$self->{_log}->debug("Module '$name' is required chain and returned unsuccessfull authentication result. Assuming that global authentication failed, returning error.");
			return 0;
		}
	}

	if ($i < 1) {
		$self->{error} = "No authentication modules are set.";
		$self->{_log}->error($self->{error});
	}

	return 0;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthDaemon>

=cut

1;