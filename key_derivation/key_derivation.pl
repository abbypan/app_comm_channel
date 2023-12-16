#!/usr/bin/perl
use strict;
use warnings;

use Crypt::OpenSSL::Base::Func;
use Crypt::OpenSSL::Bignum;

use Data::Dumper;


our $group_name = 'prime256v1';
our $nid = OBJ_sn2nid($group_name);
our $group = Crypt::OpenSSL::EC::EC_GROUP::new_by_curve_name($nid);

our $id_app = 'com.abbypan.test';
our $st = "202311061600"; 
our $i = unpack("H*", digest('SHA256', $id_app.$st));

print "app:$id_app\nst:$st\ni: $i\n\n";

my $a_id = "a";
my $a_priv_device_pem = 'a_device_priv.pem';
my $a_pub_device_pem = 'a_device_pub.pem';
my $a_priv_app_pem = 'a_account_priv.pem';
my $a_pub_app_pem = 'a_account_pub.pem';
derivate($a_id, $a_priv_app_pem, $a_pub_app_pem, $a_priv_device_pem, $a_pub_device_pem);

my $b_id = "b";
my $b_priv_device_pem = 'b_device_priv.pem';
my $b_pub_device_pem = 'b_device_pub.pem';
my $b_priv_app_pem = 'b_account_priv.pem';
my $b_pub_app_pem = 'b_account_pub.pem';
derivate($b_id, $b_priv_app_pem, $b_pub_app_pem, $b_priv_device_pem, $b_pub_device_pem);

sub derivate {
    my ($a_id, $a_priv_app_pem, $a_pub_app_pem, $a_priv_device_pem, $a_pub_device_pem) = @_;

    print "{\nid:$a_id\n\n";

    my $a_priv_device_hex = read_ec_key_from_pem($a_priv_device_pem);
    print "priv_device: $a_priv_device_hex\n";

    my $a_pub_device_hex = read_ec_pubkey_from_pem($a_pub_device_pem, 1);
    print "pub_device: $a_pub_device_hex\n\n";

    my $a_priv_app_hex = read_ec_key_from_pem($a_priv_app_pem);
    print "priv_app: $a_priv_app_hex\n";

    my $a_pub_app_hex = read_ec_pubkey_from_pem($a_pub_app_pem, 1);
    print "pub_app: $a_pub_app_hex\n\n";

    my $a_c = digest('SHA256', $a_id.pack("H*", $a_pub_device_hex));
    print "c: ", unpack("H*", $a_c), "\n\n";

    print "cross-account-use:\n";
    my ($a2_priv_app_hex, $c2) = CKDpriv($a_priv_app_hex, $a_c, $i, 'cross-account-use');
    print "xi: ", $a2_priv_app_hex, "\n";
    print "ci: ", unpack("H*", $c2), "\n";
    my $a2_priv_pkey = gen_ec_key($group_name, $a2_priv_app_hex);
    my $a2_pub_app_phex = export_pubkey($a2_priv_pkey);
    print "yi: ", $a2_pub_app_phex, "\n\n";
    my ($a2_pub_app_hex, $c2y) = CKDpub($a_pub_app_hex, $a_c, $i);
    print "yi2: ", $a2_pub_app_hex, "\n";
    print "ci2: ", unpack("H*", $c2y), "\n\n";
    write_key_to_pem("$a_id.cross_priv.pem", $a2_priv_pkey );
    write_pubkey_to_pem("$a_id.cross_pub.pem", $a2_priv_pkey );

    print "self-account-use:\n";
    my ($a3_priv_app_hex, $c3) = CKDpriv($a_priv_app_hex, $a_c, $i, 'self-account-use');
    print "xi: ", $a3_priv_app_hex, "\n";
    print "ci: ", unpack("H*", $c3), "\n";
    my $a3_priv_pkey = gen_ec_key($group_name, $a3_priv_app_hex);
    my $a3_pub_phex = export_pubkey($a3_priv_pkey);
    print "yi: ", $a3_pub_phex, "\n}\n\n";
    write_key_to_pem("$a_id.self_priv.pem", $a3_priv_pkey );
    write_pubkey_to_pem("$a_id.self_pub.pem", $a3_priv_pkey );
}


sub CKDpub {
    my ($Y, $c, $i) = @_;

    my $ctx = Crypt::OpenSSL::Bignum::CTX->new();

    my $Y_point = Crypt::OpenSSL::EC::EC_POINT::new($group);
    Crypt::OpenSSL::EC::EC_POINT::oct2point($group, $Y_point, pack("H*", $Y), $ctx);
    #print "Y: $Y\n";

    my $bn_i = Crypt::OpenSSL::Bignum->new_from_hex($i);
    my $bn_one = Crypt::OpenSSL::Bignum->one();

    while(1){
        my $i_bin = $bn_i->to_bin();
        my $I = hmac('SHA-512', $c, pack("H*", $Y).$i_bin);

        my $len = length($I)/2;
        my $IL = substr($I, 0, $len);
        my $IR = substr($I, $len, $len);

        my $priv_pkey = gen_ec_key($group_name, unpack("H*", $IL));
        my $pub_hex = export_pubkey($priv_pkey);
        my $pub_point = Crypt::OpenSSL::EC::EC_POINT::new($group);
        Crypt::OpenSSL::EC::EC_POINT::oct2point($group, $pub_point, pack("H*", $pub_hex), $ctx);
        #print "pub point: $pub_hex\n";

        my $Y2_point = Crypt::OpenSSL::EC::EC_POINT::new($group);
        Crypt::OpenSSL::EC::EC_POINT::add($group, $Y2_point, $pub_point, $Y_point, $ctx);


        my $bn_IL = Crypt::OpenSSL::Bignum->new_from_hex(unpack("H*", $IL)); 
        my $bn_q = get_pkey_bn_param($priv_pkey, "order");

        if($bn_IL->cmp($bn_q)<0 and ! Crypt::OpenSSL::EC::EC_POINT::is_at_infinity($group, $Y2_point)){
            my $y2 = Crypt::OpenSSL::EC::EC_POINT::point2oct($group, $Y2_point, &Crypt::OpenSSL::EC::POINT_CONVERSION_COMPRESSED, $ctx);
            return (unpack("H*", $y2), $IR);
        }

        $bn_i = $bn_i->add($bn_one);    
        #Yi = point($IL) + point(Y);
    }

}

sub CKDpriv {
    my ($x, $c, $i, $t) = @_;

    my $pkey = gen_ec_key($group_name, $x);
    my $Y = export_pubkey($pkey);

    my $bn_i = Crypt::OpenSSL::Bignum->new_from_hex($i);

    my $bn_one = Crypt::OpenSSL::Bignum->one();

    while(1){
        my $i_bin = $bn_i->to_bin();

        my $I;
        if($t eq 'self-account-use'){
            my $zero = 0x00;
            $I = hmac('SHA-512', $c, $zero.pack("H*", $x).$i_bin);
        }else{
            $I = hmac('SHA-512', $c, pack("H*", $Y).$i_bin);
        }

        my $len = length($I)/2;
        my $IL = substr($I, 0, $len);
        my $IR = substr($I, $len, $len);

        my $bn_x = Crypt::OpenSSL::Bignum->new_from_hex($x); 
        my $bn_IL = Crypt::OpenSSL::Bignum->new_from_hex(unpack("H*", $IL)); 
        my $bn_q = get_pkey_bn_param($pkey, "order");

        my $ctx = Crypt::OpenSSL::Bignum::CTX->new();
        my $bn_s = $bn_x->add($bn_IL);
        my $bn_x2 = $bn_s->mod($bn_q, $ctx);

        if($bn_IL->cmp($bn_q)<0 and ! $bn_x2->is_zero){
            return (BN_bn2hex($bn_x2), $IR);
        }

        $bn_i = $bn_i->add($bn_one);    
    }
}
