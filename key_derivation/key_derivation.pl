#!/usr/bin/perl
use strict;
use warnings;

use Crypt::OpenSSL::Base::Func;
use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::EC;

use Data::Dumper;
#use Smart::Comments;

my ( $act ) = @ARGV;

our $group_name = 'prime256v1';
our $nid        = OBJ_sn2nid( $group_name );
our $group      = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name( $nid );

our $app_id = 'com.abbypan.appcomm';

#our $i = unpack("H*", digest('SHA256', $id_app.$st));
my $dgstCert = pack( "H*", "227CD41304BDC2D710644C0B24A48667A7CD495B5D5AF088F22FCCDE4DBB6A04" );
my $n        = 32;

my $a_id               = "alice";
my $a_priv_device_pem  = 'a_device_priv.pem';
my $a_pub_device_pem   = 'a_device_pub.pem';
my $a_priv_account_pem = 'a_account_priv.pem';
my $a_pub_account_pem  = 'a_account_pub.pem';

my $a_xu_hex = read_key(read_key_from_pem( $a_priv_account_pem ));
my $a_xu     = gen_ec_key( $group_name, $a_xu_hex );

my $a_Yu_hex = read_ec_pubkey(read_pubkey_from_pem( $a_pub_account_pem ), 1);

my $a_xd_hex = read_key(read_key_from_pem( $a_priv_device_pem ));
my $a_xd     = gen_ec_key( $group_name, $a_xd_hex );

my $a_Yd_hex = read_ec_pubkey(read_pubkey_from_pem( $a_pub_device_pem), 1 );

if ( $act eq 'upsk' ) {
  my $upsk = CKDupsk( pack( "H*", $a_xu_hex ), $a_id, $app_id, $dgstCert, $n );
  print "upsk: ", unpack( "H*", $upsk ), "\n";
} elsif ( $act eq 'ud' ) {
  my $ud = CKDud( $a_xu, $a_id, $app_id, $dgstCert, $a_xd, pack( "H*", $a_Yd_hex ) );
  print "ud: ", unpack( "H*", $ud ), "\n";

  #my $pkey = gen_ec_key($group_name, unpack("H*", $ud));
  #my $Y = export_pubkey($pkey);
  #print "udY: ", $Y, "\n";
} elsif ( $act eq 'udpub' ) {
  my $udpub = CKDudpub( $a_xu, $a_id, $app_id, $dgstCert, pack( "H*", $a_Yu_hex ), pack( "H*", $a_Yd_hex ) );
  print "udpub: ", unpack( "H*", $udpub ), "\n";
} elsif ( $act eq 'uc' ) {
  my $uc = CKDuc( $a_xu, $a_id, $app_id, $dgstCert, pack( "H*", $a_Yu_hex ) );
  print "uc: ", unpack( "H*", $uc ), "\n";

  #my $pkey2 = gen_ec_key($group_name, unpack("H*", $uc));
  #my $Y2 = export_pubkey($pkey2);
  #print "ucY: ", $Y2, "\n";
} elsif ( $act eq 'ucpub' ) {
  my $ucpub = CKDucpub( $a_id, $app_id, $dgstCert, pack( "H*", $a_Yu_hex ) );
  print "ucpub: ", unpack( "H*", $ucpub ), "\n";
}

sub CKDupsk {
  my ( $a_xu, $a_id, $app_id, $dgstCert, $n ) = @_;

  my $i = digest( 'SHA256', $a_id . $app_id );

  #print $i, "\n";

  my $head = pack( "H*", '00' );

  my $salt = $head . $a_xu . $i;

  #print "salt:", unpack("H*", $salt), "\n";

  my $okm = hkdf( 'SHA256', $dgstCert, $salt, "CKDupsk", $n );

  return $okm;
}

sub CKDud {
  my ( $xu_pkey, $uid, $aid, $dgstCert, $xd_pkey, $Yd ) = @_;

  my $xu_hex = read_key( $xu_pkey );
  my $xu_bn  = Crypt::OpenSSL::Bignum->new_from_hex( $xu_hex );
  my $xu     = pack( "H*", $xu_hex );

  my $xd_hex = read_key( $xd_pkey );
  my $xd_bn  = Crypt::OpenSSL::Bignum->new_from_hex( $xd_hex );
  my $xd     = pack( "H*", $xd_hex );

  my $i   = digest( 'SHA256', $uid . $aid );
  my $ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $i ) );

  my $head = pack( "H*", '00' );

  #my $pkey = gen_ec_key($group_name, $x);
  #my $Y = export_pubkey($pkey);

  #my $bn_i = Crypt::OpenSSL::Bignum->new_from_hex($i);

  my $order = get_pkey_bn_param( $xu_pkey, "order" );

  my $one = Crypt::OpenSSL::Bignum->one();

  my $ctx = Crypt::OpenSSL::Bignum::CTX->new();

  while ( 1 ) {

    #my $i_bin = $bn_i->to_bin();
    my $s = $head . $xu . $Yd . $i;

    my $I   = hmac( 'SHA-256', $dgstCert, $s );
    my $Ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $I ) );

    #my $order = get_pkey_bn_param($pkey, "order");

    my $bn_s = $Ibn->add( $xu_bn )->add( $xd_bn )->mod( $order, $ctx );

    if ( $Ibn->cmp( $order ) < 0 and !$bn_s->is_zero ) {
      return $bn_s->to_bin;
    }

    $ibn = $ibn->add( $one );
    $i   = $ibn->to_bin;
  } ## end while ( 1 )
} ## end sub CKDud

sub CKDudpub {
  my ( $xu_pkey, $uid, $aid, $dgstCert, $Yu, $Yd ) = @_;

  my $xu_hex = read_key( $xu_pkey );
  my $xu_bn  = Crypt::OpenSSL::Bignum->new_from_hex( $xu_hex );
  my $xu     = pack( "H*", $xu_hex );

  my $ctx = Crypt::OpenSSL::Bignum::CTX->new();

  my $Yu_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
  Crypt::OpenSSL::EC::EC_POINT::oct2point( $group, $Yu_point, $Yu, $ctx );

  #print "Y: $Y\n";
  my $Yd_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
  Crypt::OpenSSL::EC::EC_POINT::oct2point( $group, $Yd_point, $Yd, $ctx );

  my $i   = digest( 'SHA256', $uid . $aid );
  my $ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $i ) );

  my $head   = pack( "H*", '00' );
  my $bn_one = Crypt::OpenSSL::Bignum->one();
  my $order  = get_pkey_bn_param( $xu_pkey, "order" );

  my $tmp_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
  Crypt::OpenSSL::EC::EC_POINT::add( $group, $tmp_point, $Yu_point, $Yd_point, $ctx );

  while ( 1 ) {
    my $s   = $head . $xu . $Yd . $i;
    my $I   = hmac( 'SHA-256', $dgstCert, $s );
    my $Ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $I ) );

    my $priv_pkey = gen_ec_key( $group_name, unpack( "H*", $I ) );
    my $pub_hex   = read_ec_pubkey(export_ec_pubkey( $priv_pkey ), 1);
    my $pub_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
    Crypt::OpenSSL::EC::EC_POINT::oct2point( $group, $pub_point, pack( "H*", $pub_hex ), $ctx );

    my $Yi_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
    Crypt::OpenSSL::EC::EC_POINT::add( $group, $Yi_point, $pub_point, $tmp_point, $ctx );

    if ( $Ibn->cmp( $order ) < 0 and !Crypt::OpenSSL::EC::EC_POINT::is_at_infinity( $group, $Yi_point ) ) {
      my $yi = Crypt::OpenSSL::EC::EC_POINT::point2oct( $group, $Yi_point, &Crypt::OpenSSL::EC::POINT_CONVERSION_COMPRESSED, $ctx );
      return $yi;
    }

    $ibn = $ibn->add( $bn_one );
    $i   = $ibn->to_bin;
  } ## end while ( 1 )

} ## end sub CKDudpub

sub CKDuc {
  my ( $xu_pkey, $uid, $aid, $dgstCert, $Yu ) = @_;

  my $xu_hex = read_key( $xu_pkey );
  my $xu_bn  = Crypt::OpenSSL::Bignum->new_from_hex( $xu_hex );
  my $xu     = pack( "H*", $xu_hex );

  my $i   = digest( 'SHA256', $uid . $aid );
  my $ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $i ) );

  my $head = pack( "H*", '00' );

  #my $pkey = gen_ec_key($group_name, $x);
  #my $Y = export_pubkey($pkey);

  #my $bn_i = Crypt::OpenSSL::Bignum->new_from_hex($i);

  my $order = get_pkey_bn_param( $xu_pkey, "order" );

  my $one = Crypt::OpenSSL::Bignum->one();

  my $ctx = Crypt::OpenSSL::Bignum::CTX->new();

  while ( 1 ) {

    #my $i_bin = $bn_i->to_bin();
    my $s = $head . $Yu . $i;

    my $I   = hmac( 'SHA-256', $dgstCert, $s );
    my $Ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $I ) );

    #my $order = get_pkey_bn_param($pkey, "order");

    my $bn_s = $Ibn->add( $xu_bn )->mod( $order, $ctx );

    if ( $Ibn->cmp( $order ) < 0 and !$bn_s->is_zero ) {
      return $bn_s->to_bin;
    }

    $ibn = $ibn->add( $one );
    $i   = $ibn->to_bin;
  } ## end while ( 1 )
} ## end sub CKDuc

sub CKDucpub {
  my ( $uid, $aid, $dgstCert, $Yu ) = @_;

  my $ctx = Crypt::OpenSSL::Bignum::CTX->new();

  #my $order = Crypt::OpenSSL::EC::EC_GROUP::get_order($group, $order, $ctx);
  my $order = Crypt::OpenSSL::Bignum->one();
  Crypt::OpenSSL::EC::EC_GROUP::get_order( $group, $order, $ctx );

  my $Yu_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
  Crypt::OpenSSL::EC::EC_POINT::oct2point( $group, $Yu_point, $Yu, $ctx );

  #print "Y: $Y\n";

  my $i   = digest( 'SHA256', $uid . $aid );
  my $ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $i ) );

  my $head   = pack( "H*", '00' );
  my $bn_one = Crypt::OpenSSL::Bignum->one();

  #my $order = get_pkey_bn_param($xu_pkey, "order");

  #my $tmp_point = Crypt::OpenSSL::EC::EC_POINT::new($group);
  #Crypt::OpenSSL::EC::EC_POINT::add($group, $tmp_point, $Yu_point, $Yd_point, $ctx);

  while ( 1 ) {
    my $s   = $head . $Yu . $i;
    my $I   = hmac( 'SHA-256', $dgstCert, $s );
    my $Ibn = Crypt::OpenSSL::Bignum->new_from_hex( unpack( "H*", $I ) );

    my $priv_pkey = gen_ec_key( $group_name, unpack( "H*", $I ) );
    my $pub_hex   = read_ec_pubkey(export_ec_pubkey( $priv_pkey ), 1);
    my $pub_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
    Crypt::OpenSSL::EC::EC_POINT::oct2point( $group, $pub_point, pack( "H*", $pub_hex ), $ctx );

    my $Yi_point = Crypt::OpenSSL::EC::EC_POINT::new( $group );
    Crypt::OpenSSL::EC::EC_POINT::add( $group, $Yi_point, $pub_point, $Yu_point, $ctx );

    if ( $Ibn->cmp( $order ) < 0 and !Crypt::OpenSSL::EC::EC_POINT::is_at_infinity( $group, $Yi_point ) ) {
      my $yi = Crypt::OpenSSL::EC::EC_POINT::point2oct( $group, $Yi_point, &Crypt::OpenSSL::EC::POINT_CONVERSION_COMPRESSED, $ctx );
      return $yi;
    }

    $ibn = $ibn->add( $bn_one );
    $i   = $ibn->to_bin;
  } ## end while ( 1 )

} ## end sub CKDucpub
