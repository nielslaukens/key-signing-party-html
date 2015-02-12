#!/usr/bin/env perl

# Convert a "raw" (--with-colons) keylist
#   gpg --no-options --fingerprint --list-keys --with-colons --fixed-list-mode
# in to a text keylist

use strict;
use warnings;
use File::Temp qw/tempdir/;
use HTML::Entities;
use File::Basename;
use Imager::QRCode;
use MIME::Base64;


my $keyring = "keyring.gpg";
if( @ARGV == 1 ) {
        $keyring = $ARGV[0];
}

use File::Temp qw/tempdir/;
use HTML::Entities;
use File::Basename;
use lib dirname(__FILE__) . "/lib";
use KeylistParseRaw;

binmode STDOUT, ':encoding(utf8)';

my $tempdir = tempdir(CLEANUP => 1);
my $rv = system("gpg", "--homedir", $tempdir, "-q", "--import", $keyring) >> 8;
if( $rv != 0 ) {
	die "Usage: $0 keyring.gpg\n";
}

open my $keys_fh, "gpg --homedir \"$tempdir\" --list-keys --with-fingerprint --with-colons --fixed-list-mode |"
        or die "Could not list keys";
my @key = KeylistParseRaw::parse($keys_fh);

sub epoch_to_date {
	my ($epoch) = @_;
	my ($sec, $min, $hour, $day,$month,$year) = (localtime($epoch))[0,1,2,3,4,5];
	return sprintf("%d-%02d-%02d", $year+1900, $month+1, $day);
}

sub format_fingerprint {
	my ($fp) = @_;
	# GnuPG formats it as ".... .... .... .... ....  .... .... .... .... ...."
	my @fp = ($fp =~ m/(....)/g);
	splice @fp, 5, 0, '';
	return join " ", @fp;
}

sub unique_uids {
# This needs to reflect your policy!
	my %uid;
	my $uat = 0;
	for my $uid (@_) {
		if( $uid->{type} eq 'uid' ) {
			my $cleanuid = $uid->{uid};
			no warnings 'uninitialized';
			$cleanuid =~ s/ <[^<]+>$//; # remove email-address
			$cleanuid =~ s/ \([^(]+\)$//; # remove trailing comments
			$cleanuid = encode_entities($cleanuid, "<>&");
			$uid{ $cleanuid }++;
		} elsif( $uid->{type} eq 'uat' ) {
			$uat++
		} else {
			die "unknown UID type " . $uid->{type};
		}
	}
	my @out = map { ($_ ne "" ? "<code>$_</code>" : "[undefined]") . " (" . $uid{$_} . ")" }
		sort { length($b) <=> length($a) } keys(%uid);
	if( $uat ) {
		push @out, $uat . " UATs";
	}
	return @out;
}


print <<'EOT';
	<html>
	 <head>
	  <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
	  <title>FOSDEM keysigning event keylist</title>
	  <style>
		div.key {
			border: 1pt solid black;
			margin: 6pt;
			padding: 4pt;
		}
		@media print { div.key {page-break-inside: avoid;} }
		div.num {
			font-size: 130%;
			display: inline-block;
			margin-right: 12pt;
		}
		div.pub {
			display: inline-block;
		}
		div.fingerprint:before {
			content: "";
			border: 1pt solid black;
			width: 10pt;
			height: 10pt;
			display: inline-block;
			margin-right: 5pt;
		}
		div.uid:before {
			content: "";
			border: 1pt solid black;
			width: 10pt;
			height: 10pt;
			display: inline-block;
			margin-right: 5pt;
		}
	  </style>
	 </head>
	 <body>
EOT

my $i = 1;
for my $key (@key) {
	print '<div class="key">';
	print "<div class=\"num\">" . $i++ . "</div>";
	printf "<div class=\"pub\">pub   %s%s%d/%s %s%s</div>\n",
		$KeylistParseRaw::algo{ $key->{algo} },
		(defined $key->{curve} ? $key->{curve} : ""),
		$key->{key_length},
		substr($key->{keyid},8), epoch_to_date($key->{create_date}),
		($key->{expire_date} ne '' ? " [expires: " . epoch_to_date($key->{expire_date}) . "]" : "");
	print "<div class=\"fingerprint\">Key fingerprint = ",
		format_fingerprint($key->{fingerprint}),
		"</div>\n";

	# Try to reduce the number of UIDs
	my @uid = unique_uids @{$key->{uid}};

	for my $uid (@uid) {
		print "<div class=\"uid\">$uid</div>\n";
	}
	print "</div>\n";
}

print <<'EOT'
	  </pre>
	 </body>
	</html>
EOT
