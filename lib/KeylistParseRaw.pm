package KeylistParseRaw;

# Convert a "raw" (--with-colons) keylist
#   gpg --no-options --fingerprint --list-keys --with-colons --fixed-list-mode
# in to a perl array

use strict;
use warnings;
use Encode;

sub uid_decode {
	my ($uid) = @_;
	# decode \x12 escapes
	$uid =~ s/\\x(..)/ chr(hex($1)) /eg;
	eval { $uid = decode( 'utf8', $uid, Encode::FB_CROAK ) }
	      or return undef;
	return $uid;
}

our %algo = (
	1 => "rsa", # RSA
	2 => "rsa", # RSA Encrypt-Only
	3 => "rsa", # RSA Sign-Only
	16 => "elg", # Elgamal (Encrypt-Only)
	17 => "dsa", # DSA
	18 => "", # ECDH, print curve
	19 => "", # ECDSA, print curve
	20 => "elg", # Elgamal (Encrypt+Sign)
);

sub parse {
	my ($fh) = @_;
	my @key;
	my %current_key;
	while(<$fh>) {
		my @field = split /:/, $_, -1;
		if( $field[0] eq 'pub' ) {
			# push a copy of current_key
			push @key, {%current_key} if defined $current_key{keyid};
			%current_key = ();

			#$current_key{validity} = $field[1];
			$current_key{key_length} = $field[2];
			$current_key{algo} = $field[3];
			$current_key{keyid} = $field[4];
			$current_key{create_date} = $field[5];
			$current_key{expire_date} = $field[6];
			# $field[7] # Certificate S/N, UID hash, trust signature info
			# $field[8] # Ownertrust
			# $field[9] # UID, not for --fixed-list-mode
			# $field[10] # Signature class
			$current_key{key_capabilities} = $field[11]; # Key capabilities
			# $field[12] # Issuer certificate fingerprint or other info
			# $field[13] # Flag field
			# $field[14] # S/N of a token
			# $field[15] # Hash algorithm
			$current_key{curve_name} = $field[16];

		} elsif( $field[0] eq 'fpr' ) {
			$current_key{fingerprint} = $field[9];

		} elsif( $field[0] eq 'uid' ) {
			my %uid;
			$uid{type} = 'uid';
			$uid{create_date} = $field[5];
			$uid{uid} = uid_decode($field[9]);
			$current_key{uid} = [] if ! defined $current_key{uid};
			push @{$current_key{uid}}, \%uid;

		} elsif( $field[0] eq 'uat' ) {
			my %uat;
			$uat{type} = 'uat';
			$uat{create_date} = $field[5];
			$uat{hash} = $field[7];	
			($uat{packets}, $uat{total_size}) = split / /, $field[9];
			$current_key{uid} = [] if ! defined $current_key{uid};
			push @{$current_key{uid}}, \%uat;

		} elsif( $field[0] eq 'crt' ) { # ignore X.509 certificate
		} elsif( $field[0] eq 'crs' ) { # ignore X.509 certificate and private key available
		} elsif( $field[0] eq 'sub' ) { # ignore Subkeys
		} elsif( $field[0] eq 'sec' ) { # ignore Secret key
		} elsif( $field[0] eq 'ssb' ) { # ignore Secret subkey (secondary key)
		} elsif( $field[0] eq 'sig' ) { # ignore Signature
		} elsif( $field[0] eq 'rev' ) { # ignore Revocation signature
		} elsif( $field[0] eq 'pkd' ) { # ignore Public key data
		} elsif( $field[0] eq 'grp' ) { # ignore Keygrip
		} elsif( $field[0] eq 'rvk' ) { # ignore Revocation key
		} elsif( $field[0] eq 'tru' ) { # ignore Trust info
		} elsif( $field[0] eq 'spk' ) { # ignore Signature subpacket
		} elsif( $field[0] eq 'cfg' ) { # ignore Configuration data
		} else {
			#print "Unknown line: $_";
		}
	}
	push @key, {%current_key} if defined $current_key{keyid};
	return @key;
}
