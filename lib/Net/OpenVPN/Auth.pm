package Net::OpenVPN::Auth;

use strict;
use warnings;

my $Error = "";

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = {};

	##################################################
	#               PUBLIC VARS                      #
	##################################################

	##################################################
	#              PRIVATE VARS                      #
	##################################################
	$self->{_name} = "CHANGE_THIS_IN_YOUR_MODULE";

	bless($self, $class);
	$self->clearParams();
	$self->setParams(@_);

	return $self;
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

sub clearParams {
	my ($self) = @_;
	$self->{error} = "";
	$self->{required} = 1;
	$self->{sufficient} = 0;
	return 1;
}

sub getError {
	my $self = shift;
	return $self->{error} if (ref($self));
	return $Error;
}

sub getDrivers {
	my(@drivers, %seen_dir);
	local (*DIR, $@);
	my $package = __PACKAGE__;
	$package =~ s/::/\//g;

	foreach  my $d (@INC) {
		chomp($d);
		my $dir = $d . "/" . $package;

		next unless (-d $dir);
		next if ($seen_dir{$d});

		$seen_dir{$d} = 1;

		next unless (opendir(DIR, $dir));
		foreach my $f (readdir(DIR)){
			next unless ($f =~ s/\.pm$//);
			next if ($f eq 'NullP');
			next if ($f eq 'EXAMPLE');
			next if ($f =~ m/^_/);

			# this driver seems ok, push it into list of drivers
			push(@drivers, $f) unless ($seen_dir{$f});
			$seen_dir{$f} = $d;
		}
		closedir(DIR);
	}

	# "return sort @drivers" will not DWIM in scalar context.
	return (wantarray ? sort @drivers : @drivers);
}

sub factory {
	my $ref = ref($_[0]);
	my $self = undef;
	if (length($ref) > 0) {
		if ($_[0]->isa(__PACKAGE__)) {
			$self = shift;
		}
	}
	elsif ($_[0] eq __PACKAGE__) {
		shift;
	}

	my $driver = shift;
	unless (defined $driver && length($driver) > 0) {
		$Error = "Driver name was not specified.";
		$self->{error} = $Error if (defined $self);
		return undef;
	}

	my $fullpkg = __PACKAGE__ . "::" . $driver;

	# try to load module
	my $str = "require " . $fullpkg;
	eval $str;

	# check for injuries
	if ($@) {
		$Error = "Unable to load driver module '$fullpkg': $@";
		$Error =~ s/\s+$//g;
		$self->{error} = $Error if (defined $self);
		return undef;
	}

	# initialize object
	my $obj = undef;
	eval {
		$obj = ($fullpkg)->new(@_);
	};
	
	if ($@) {
		$Error = "Unable to create $driver object: $@";
		$Error =~ s/\s+$//g;
		$self->{error} = $Error if (defined $self);
		return undef;
	}
	
	eval {
		$obj->{_log}->info("Authentication module initialized: $driver.");
	};

	return $obj;
}

sub isRequired {
	my ($self) = @_;
	return $self->{required};
}

sub isSufficient {
	my ($self) = @_;
	return $self->{sufficient};
}

sub getName {
	my ($self) = @_;
	return $self->{_name};
}

sub setName {
	my ($self, $name) = @_;
	$self->{error} = "";
	unless (defined $name) {
		$self->{error} = "Undefined name";
		return 0;
	}

	$self->{_name} = $name;
	return 1;
}

sub validateParamsStruct {
	my ($self, $struct) = @_;
	my $r = 0;
	$self->{error} = "";
	if (! defined $struct->{username}) {
		$self->{error} = "Username is not defined.";
	}
	elsif (! defined $struct->{password}) {
		$self->{error} = "Password is not set.";
	}
=pod
	elsif (! defined $struct->{common_name}) {
		$self->{error} = "Certificate common name is unknown.";
	}
	elsif (! defined $struct->{host}) {
		$self->{error} = "Remote host is unknown.";
	}
	elsif (! $struct->{port}) {
		$self->{error} = "Unknown remote port.";
	}
=cut
	else {
		$r = 1;
	}
	
	unless ($r) {
		$self->{error} = "Invalid input structure: " . $self->{error};
		$self->{_log}->error($self->{error});
	}
	
	return $r;
}

sub newParamsStruct {
	return {
		username => undef,
		password => undef,
		common_name => undef,
		untrusted_ip => undef,
		untrusted_port => undef
	};
}

sub authenticate {
	my ($self, $struct) = @_;
	$self->{error} = "This method must be implemented by the driver class.";
	return 0;
}

=head1 AUTHOR

Brane F. Gracnar

=cut

=head1 SEE ALSO

L<Net::OpenVPN::AuthChain>
L<Net::OpenVPN::AuthDaemon>

=cut

1;