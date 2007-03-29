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

package Net::OpenVPN::PasswordValidator;

use strict;
use warnings;

# Supported password hashes
my @HASHES = (
	# [ 'name', 'Perl::Module', 'description']
	[ 'PLAIN', 'IO::File', 'Cleartext password.' ],
	[ 'CRYPT',  'IO::File', 'Old, traditional crypt(3) hashed password with 2 character salt.' ],
	[ 'CRYPTMD5',  'Crypt::PasswdMD5', 'Modular crypt(3) MD5 hashed password with 8 character salt.' ],
	[ 'MD5', "Digest::MD5", 'MD5 string digest.' ],
	[ 'SHA1', "Digest::SHA1", 'SHA1 string digest.' ],
	[ 'NTLM', "Crypt::SmbHash", 'NT LanManager hashed password.' ],
#	[ 'SSHA', "Crypt::SaltedHash", 'Salted SHA1 hashed password with 16byte salt.' ],
	[ 'TIGER', "Digest::Tiger", 'Tiger string digest.' ],
	[ 'WHIRLPOOL', "Digest::Whirlpool", "Whirlpool string digest." ],
);

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = {};

	##################################################
	#               PUBLIC VARS                      #
	##################################################
	$self->{hash} = "PLAIN";
	$self->{error} = "";

	bless($self, $class);
	$self->_init();
	return $self;
}

##################################################
#               PUBLIC  METHODS                  #
##################################################

sub getError {
	my ($self) = @_;
	return $self->{error};
}

sub getSupported {
	my ($self) = @_;
	my @tmp = ();
	
	map {
		push(@tmp, $_->[0]);
	} @HASHES;

	return sort @tmp;
}

sub getEnabled {
	my ($self) = @_;
	my @tmp = ();

	map {
		if ($_ =~ m/^_has_(.+)/ && $self->{$_}) {
			push(@tmp, $1);		
		}
	} keys(%{$self});

	return sort @tmp;
}

sub isEnabled {
	my ($self, $hash) = @_;
	my $str = "_has_" . $hash;

	if (! exists($self->{$str})) {
		$self->{error} = "Unsupported password hashing algorithm.";
		return 0;
	}
	elsif (! $self->{$str}) {
		$self->{error} = "Supported, but disabled hashing algorithm. Probably perl module " . $self->getRequiredModule($hash) . " is not installed.";
		return 0;
	}

	return 1;
}

sub getRequiredModule {
	my ($self, $hash) = @_;
	map {
		if ($_->[0] eq $hash) {
			return $_->[1];
		}
	} @HASHES;

	$self->{error} = "Unsupported password hashing algorithm.";
	return undef;
}

sub getDescription {
	my ($self, $hash) = @_;
	map {
		if ($_->[0] eq $hash) {
			return $_->[2];
		}
	} @HASHES;

	$self->{error} = "Unsupported password hashing algorithm.";
	return undef;
}

sub getPasswordHash {
	my ($self) = @_;
	return $self->{hash};
}

sub setPasswordHash {
	my ($self, $hash) = @_;
	$self->{hash} = $hash;
}

sub validatePassword {
	my ($self, $hashed_pw, $clear_pw, $hash_type) = @_;
	$hash_type = $self->{hash} unless (defined $hash_type);
	
	my $str = "_has_" . $hash_type;
	unless (exists($self->{$str}) && $self->{$str}) {
		$self->{error} = "Unsupported password hashing algorithm: $hash_type";
		return 0;
	}
	
	# safely validate password
	$str = "_validate" . $hash_type;
	my $r = 0;
	eval {
		$r = $self->$str($hashed_pw, $clear_pw);		
	};
	
	if ($@) {
		$self->{error} = "Error validating password: $@";
		return 0;
	}
	
	# return validation result
	return $r;
}

##################################################
#               PRIVATE METHODS                  #
##################################################

sub _init {
	my ($self) = @_;
	
	# probe for available hashes...
	foreach my $opt (@HASHES) {
		my $str = "require " . $opt->[1];
		eval $str;
		$self->{"_has_" . $opt->[0]} = ($@) ? 0 : 1;
	}

	return 1;
}

# PLAIN
sub _validatePLAIN {
	my ($self, $hash, $password) = @_;
	if ($password ne $hash) {
		$self->{error} = "Invalid password.";
		return 0;
	}
	return 1;
}

# crypt(3)
sub _validateCRYPT {
	my ($self, $hash, $password) = @_;
	my $salt = substr($hash, 0, 2);
	if ($hash ne crypt($password, $salt)) {
		$self->{error} = "Invalid password.";
		return 0;
	}
	return 1;
}

# MD5 crypt(3)
sub _validateCRYPTMD5 {
	my ($self, $hash, $password) = @_;
	my $salt = substr($hash, 3, 8);
	if ($hash ne Crypt::PasswdMD5::unix_md5_crypt($password, $salt)) {
		$self->{error} = "Invalid password.";
		return 0;
	}

	return 1;
}

# MD5 digest
sub _validateMD5 {
	my ($self, $hash, $password) = @_;
	if ($hash ne Digest::MD5::md5_hex($password)) {
		$self->{error} = "Invalid password.";
		return 0;
	}

	return 1;
}

# SHA1 digest
sub _validateSHA1 {
	my ($self, $hash, $password) = @_;
	if ($hash ne Digest::SHA1::sha1_hex($password)) {
		$self->{error} = "Invalid password.";
		return 0;
	}

	return 1;
}

# NTLM
sub _validateNTLM {
	my ($self, $hash, $password) = @_;
	if ($hash ne Crypt::SmbHash::ntlmgen($password)) {
		$self->{error} = "Invalid password.";
		return 0;
	}

	return 1;
}

# salted SHA
sub _validateSSHA {
	my ($self, $hash, $password) = @_;
	
	# TODO implement SSHA password hashing
	$self->{error} = "Salted hashing algorithms are currently not implemented.";
	return 0;
}


# TIGER
sub _validateTIGER {
	my ($self, $hash, $password) = @_;
	if ($hash ne Digest::Tiger::hexhash($password)) {
		$self->{error} = "Invalid password.";
		return 0;
	}

	return 1;
}

# WHIRLPOOL
sub _validateWHIRLPOOL {
	my ($self, $hash, $password) = @_;	
	my $h = Digest::Whirlpool->new();
	if ($hash ne $h->hexdigest($password)) {
		$self->{error} = "Invalid password.";
		return 0;	
	}

	return 1;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Digest::MD5>
L<Digest::SHA1>
L<Digest::Tiger>
L<Digest::Whirlpool>
L<Crypt::PasswdMD5>
L<Crypt::SmbHash>
L<crypt(3)>

=cut

1;
