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

package Net::OpenVPN::ClientConfig;

use strict;
use warnings;

use IO::File;
use IO::Scalar;
use Log::Log4perl;
use POSIX qw(strftime);

use constant TEMPLATE => "
#
# WHAT: OpenVPN client configuration file
# BY:   %{MYNAME} version %{VERSION} on %{DATE}
#

%{META_INFO}

%{CONFIG}

# EOF";

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

sub _init {
	my ($self) = @_;
	return 1;
}

sub entry2File {
	my ($self, $entry, $file) = @_;
	my $fd = IO::File->new($file, 'w');
	unless (defined $fd) {
		$self->{error} = "Unable to open file '$file' for writing: $!";
		return 0;
	}
	
	return $self->entry2Fd($fd);
}

sub entry2String {
	my ($self, $entry, $str) = @_;
	unless (defined $str && ref($str) eq 'SCALAR') {
		$self->{error} = "Invalid argument (not a scalar reference).";
		return 1;
	}
	
	my $fd = IO::Scalar->new($str, 'w');
	unless (defined $fd) {
		$self->{error} = "Unable to open filehandle on scalar reference: $!";
		return 0;
	}
	
	return $self->entry2Fd($fd);
}

sub entry2Fd {
	my ($self, $entry, $fd) = @_;

	my $str = TEMPLATE;
	
	my $date = strftime("%Y/%m/%d \@ %H:%M:%S", localtime(time()));
	
	# substitute magic placeholders
	$str =~ s/%{DATE}/$date/gm;
	
	unless (print $fd $str) {
		$self->{error} = "Unable to write configuration: $!";
		return 0;
	}

	# flush fd...	
	$fd->flush();

	return 1;
}

1;