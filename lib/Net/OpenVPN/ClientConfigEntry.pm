package Net::OpenVPN::ClientConfigEntry;

use strict;
use warnings;

use IO::File;
use IO::Scalar;
use Log::Log4perl;
use POSIX qw(strftime);

use constant CFG_BOOL => 1;
use constant CFG_STR => 2;
use constant CFG_INT => 3;
use constant CFG_STR_ARR => 4;

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
	my $self = {};

	##################################################
	#               PUBLIC VARS                      #
	##################################################

	##################################################
	#              PRIVATE VARS                      #
	##################################################
	$self->{_error} = "";
	$self->{_log} = Log::Log4perl->get_logger(__PACKAGE__);

	bless($self, $class);

	# initialize object
	$self->reset();
	$self->setValue(@_);

	return $self;
}

sub getError {
	my ($self) = @_;
	return $self->{_error};
}

sub setValue {
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

sub getValue {
	my ($self, $name) = @_;
	return undef unless ($self->isValidKey($name));
	return $self->{$name};
}

sub isValidKey {
	my ($self, $name) = @_;
	unless (exists($self->{$name})) {
		$self->{_error} = "Invalid key: $name";
		return 0;
	}

	return 1;
}

sub reset {
	my ($self) = @_;
	foreach my $k (keys %{$openvpn_config_types}) {
		$self->{$k} = undef;
	}

	return 1;
}

sub toFile {
	my ($self, $entry, $file) = @_;
	my $fd = IO::File->new($file, 'w');
	unless (defined $fd) {
		$self->{_error} = "Unable to open file '$file' for writing: $!";
		return 0;
	}
	
	return $self->toFd($fd);
}

sub toString {
	my ($self, $entry, $str) = @_;
	unless (defined $str && ref($str) eq 'SCALAR') {
		$self->{_error} = "Invalid argument (not a scalar reference).";
		return 1;
	}
	
	my $fd = IO::Scalar->new($str, 'w');
	unless (defined $fd) {
		$self->{_error} = "Unable to open filehandle on scalar reference: $!";
		return 0;
	}
	
	return $self->toFd($fd);
}

sub toFd {
	my ($self, $entry, $fd) = @_;

	# get template string
	my $str = TEMPLATE;	
	
	# and replace magic placeholders with
	# variables...
	my $date = strftime("%Y/%m/%d \@ %H:%M:%S", localtime(time()));
	
	# substitute magic placeholders
	$str =~ s/%{DATE}/$date/gm;
	
	# get configuration parameters as str
	my $config_str = $self->_cfgAsStr();
	$str =~ s/%{CONFIG}/$config_str/gm;

	# write and flush fd...
	unless (print $fd $str) {
		$self->{_error} = "Unable to write configuration: $!";
		return 0;
	}		
	$fd->flush();

	return 1;
}

sub _cfgAsStr {
	my ($self) = @_;
	my $str = "";

	# first print special params...
	foreach my $p ("push-reset", "ifconfig-push") {
		# try to fetch value...
		my $v = $self->_paramAsStr($p);
		next unless (defined $v);		
		$str .= $v . "\n";
	}

	# write other params
	foreach my $p (sort(keys %{$openvpn_config_types})) {
		# push-reset should be skipped
		next if ($p eq 'push-reset' || $p eq 'ifconfig-push');

		# try to fetch value...
		my $v = $self->_paramAsStr($p);
		next unless (defined $v);
		$str .= "$v" . "\n";
	}

	return $str;
}

sub _paramAsStr {
	my ($self, $name) = @_;

	# sanity check...
	return undef unless (exists($openvpn_config_types->{$name}) && defined($openvpn_config_types->{$name}));

	my $type = $openvpn_config_types->{$name};
	my $v = $self->{$name};
	my $r = "";

	if ($type == CFG_BOOL) {
		$v = lc($v);
		$r = ($v eq 'true' || $v eq 'yes' || $v eq 'y' || $v eq '1') ? $name : undef;
	}
	elsif ($type == CFG_STR) {
		 $r = 'push "' . $name . " " . $v . '"'; 
	}
	elsif ($type == CFG_INT) {
		$r = 'push "' . $name . " " . int($v) . '"';
	}
	elsif ($type == CFG_STR_ARR) {
		$r = "";
		foreach my $e (@{$self->{$name}}) {
			$r .= 'push "' . $name . " " . $e . '"' . "\n";
		}
		$r =~ s/\s+$//g;
	}
	else {
		$self->{_error} = "Invalid openvpn configuration parameter: '$name'";
		$self->{_log}->warn($self->{_error});
		$r = undef;
	}

	return $r;
}

1;