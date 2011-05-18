package Net::OpenVPN::Auth::File;

@ISA = qw(Net::OpenVPN::Auth);

use strict;
use warnings;

use IO::File;
use Log::Log4perl;

# my modules
use Net::OpenVPN::PasswordValidator;

=head1 NAME File

Password file backend authentication module

=cut

=head1 OBJECT CONSTRUCTOR

=head2 Inherited parameters

B<required> (boolean, 1) successfull authentication result is required for authentication chain to return successful authentication

B<sufficient> (boolean, 0) successful authentication result is sufficient for entire authentication chain 

=over

=head2 Module specific parameters

B<password_hash> (string, PLAIN) password hashing algorithm. List of supported and enabled password hashing algorithms can be obtained via
openvpn_authd.pl --list-pwalgs command.

B<file> (string, "") Password filename. This file is read on every authentication request if B<file_read_once> is set to B<0>, otherwise is read on object
initialization into memory. 

B<file_read_once> (boolean, 0) Read password file specified by B<file> property only on object initialization. This is very useful if openvpn_authd runs
in chroot jail and you don't want to put password file into chroot jail.   

B<split_regex> (string, "/:/") Password file must be somehow parsed to fetch username and password. File is read line by line, therefore each line must
contain username and password separated by some field delimited. This option must be in the following syntax:

 /REGEX/flags

B<username_index> (integer, 0) Username field number in by B<split_regex> property exploded string (starting with 0)

B<password_index> (integer, 1) Password field number in by B<split_regex> property exploded string (starting with 0)

=head2 EXAMPLES

Password file:
 --- snip ---
 user1:password_hash_1
 user2:password_hash_2
 --- snip ---

B<split_regex> = /:/
B<username_index> = 0
B<username_index> = 1

Password file:
 --- snip ---
 user1 password_hash_1
 user2 password_hash_2
 --- snip ---

B<split_regex> = / /
B<username_index> = 0
B<username_index> = 1


Password file:
 --- snip ---
 password_hash_1:user1
 password_hash_2:user2
 --- snip ---

B<split_regex> = /:/
B<username_index> = 1
B<username_index> = 0

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
	$self->{_name} = "File";
	$self->{_split_regex} = undef;		# compiled split regex

	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);
	bless($self, $class);
	
	# initialize object
	$self->_init();
	$self->clearParams();
	$self->setParams(@_);

	# should we read entire password into memory?
	if ($self->{file_read_once}) {
		$self->_readFileToInstance();
	}

	return $self;
}

sub clearParams {
	my ($self) = @_;
	$self->SUPER::clearParams();

	$self->{password_hash} = "CRYPTMD5";
	$self->{file} = "";
	$self->{file_read_once} = 0;
	$self->{split_regex} = "/:/";
	$self->{username_index} = 0;
	$self->{password_index} = 1;

	$self->{_split_regex} = undef;
	$self->{_data} = {};

	return 1;
}

sub authenticate {
	my ($self, $struct) = @_;
	$self->{_log}->debug("Startup.");
	return 0 unless ($self->validateParamsStruct($struct));
	
	# fetch password hash
	my $hash = $self->_getPasswordHash($struct->{username});
	unless (defined $hash) {
		$self->{_log}->error($self->{error});
		return 0;
	}

	$self->{_log}->debug("Fetched password hash: '$hash'.");

	# validate password
	$self->{_log}->debug("Validating password using '$self->{password_hash}' hashing algorithm.");
	my $result = $self->{_validator}->validatePassword($hash, $struct->{password}, $self->{password_hash});
	unless ($result) {
		$self->{error} = $self->{_validator}->getError();
	}

	return $result;
}

# initializes module
sub _init {
	my ($self) = @_;

	# create password validator object
	$self->{_validator} = Net::OpenVPN::PasswordValidator->new();

	return 1;
}

# retrieves password hash
sub _getPasswordHash {
	my ($self, $username) = @_;
	if ($self->{file_read_once}) {
		return $self->_getPasswordHashMem($username);
	} else {
		return $self->_getPasswordHashFile($username);
	}
}

sub _getPasswordHashMem {
	my ($self, $username, $data) = @_;
	$data = $self->{_data} unless (defined $data);

	if (! exists($data->{$username})) {
		$self->{error} = "Username not found.";
		$self->{_log}->debug($self->{error});
		return undef;
	}
	elsif (! defined($data->{$username})) {
		$self->{error} = "Undefined password.";
		$self->{_log}->debug($self->{error});
		return undef;
	}

	# just return goddamn password hash
	return $data->{$username};
}

sub _getPasswordHashFile {
	my ($self, $username) = @_;
	my $data = $self->_readFile($self->{file}, $username);
	return undef unless (defined $data);
	return $self->_getPasswordHashMem($username, $data);
}

sub _readFile {
	my ($self, $file, $search_username) = @_;
	$self->{error} = "";
	my $result = {};

	return undef unless (defined $self->{_split_regex} || $self->_compileSplitPattern());
	
	# open file
	$self->{_log}->debug("Opening password file '" . $file . "'.");
	my $fd = IO::File->new($file, "r");
	unless (defined $fd) {
		$self->{error} = "Unable to open password file '" . $file . "': $!";
		$self->{_log}->error($self->{error});
		return undef;
	}

	# read && parse file
	$self->{_log}->debug("Parsing password file.");
	while (<$fd>) {
		# skip comments and empty lines
		next if (/^\s*#/);
		next if (/^\s+/);

		# remove newlines
		$_ =~ s/[\r\n]+$//g;
		next unless (length($_) > 0);

		# time to explode string
		my @tmp = split($self->{_split_regex}, $_);
		next unless (@tmp);
		next unless (defined $tmp[$self->{username_index}]);
		
		my $username = $tmp[$self->{username_index}];
		my $pwhash = $tmp[$self->{password_index}];
		
		# return immediately if we do not want
		# entire hash structure...
		if (defined $search_username) {
			if ($username eq $search_username) {
				$result->{$username} = $pwhash;
				goto outta_parse;
			}
		} else {
			# store into hash
			$result->{$username} = $pwhash;
		}
	}

	outta_parse:

	# close file
	$self->{_log}->debug("Closing password file.");
	$fd->close();
	$fd = undef;

	return $result;
}

sub _readFileToInstance {
	my ($self) = @_;
	$self->{_log}->info("Reading password file '$self->{file}' into memory.");
	my $data = $self->_readFile($self->{file});
	if (defined $data) {
		$self->{_data} = $data;
		return 1;
	}
	
	return 0;
}

# compiles split pattern
sub _compileSplitPattern {
	my ($self) = @_;
	my ($reg_text, $reg_result, $flags);

	# PATTERN: /something/flags
	if ($self->{split_regex} =~ m/\/(.+)\/([imosx]{1,5})?\s*$/) {
		$reg_text = $1;
		$flags = (defined $2) ? $2 : '';
		$reg_result = "";
	} else {
		$self->{error} = "Invalid split pattern '" . $self->{split_regex} . "': Not in /pattern/flags format.";
		$self->{_log}->error($self->{error});
		return 0;
	}

	# try to compile regex
	eval { $self->{_split_regex} = qr/(?$flags:$reg_text)/; };

	if ($@ || ! defined($self->{_split_regex})) {
		$self->{error} = "Invalid split regular expression '" . $self->{split_regex} . "': " . $@;
		return 0;
	}
	return 1;
}

=head1 AUTHOR

Brane F. Gracnar, <bfg@frost.ath.cx>

=cut

=head1 SEE ALSO

L<Net::OpenVPN::Auth>
L<Net::OpenVPN::AuthChain>
L<perl_re>

=cut

1;