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