#!/usr/bin/env perl

# Convert a "raw" (--with-colons) keylist
#   gpg --no-options --fingerprint --list-keys --with-colons --fixed-list-mode
# in to a text keylist

use strict;
use warnings;

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
if( $rv != 0 ) { die "Could not import keyring"; }

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


print <<'EOT';
	<html>
	 <head>
	  <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
	  <title>FOSDEM keysigning event keylist</title>
	  <style>
	   @media print { pre {page-break-inside: avoid;} }
	  </style>
	 </head>
	 <body>
	  <pre>
EOT

my $i = 0;
for my $key (@key) {
	printf "%03d  [ ] Fingerprint OK        [ ] ID OK\n", ++$i;
	printf "pub   %s%s%d/%s %s%s\n",
		$KeylistParseRaw::algo{ $key->{algo} },
		(defined $key->{curve} ? $key->{curve} : ""),
		$key->{key_length},
		substr($key->{keyid},8), epoch_to_date($key->{create_date}),
		($key->{expire_date} ne '' ? " [expires: " . epoch_to_date($key->{expire_date}) . "]" : "");
	print "      Key fingerprint = ", format_fingerprint($key->{fingerprint}), "\n";
	for my $uid (@{$key->{uid}}) {
		if( $uid->{type} eq 'uid' ) {
			if( defined $uid->{uid} ) {
				printf "uid %s\n", encode_entities($uid->{uid}, "<>&");                    
			} else {
				print "<malformed UTF-8 uid>\n";
			}
		} elsif( $uid->{type} eq 'uat' ) {
			#printf "uat %d packet(s), %d byte(s)\n", $uid->{packets}, $uid->{total_size};
		} else {
			die "Unknown uid type";
		}
	}
	print "---------------------------------------------------------------------</pre><pre>\n";
	print "\n";
}

print <<'EOT'
	  </pre>
	 </body>
	</html>
EOT
