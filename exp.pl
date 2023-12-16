#!/usr/bin/perl
use strict;
use warnings;
use IPC::Cmd qw/run/;

my $cnt = 1000;
my $timeout = 120;
my $retry = 30;

my @files = qw[
resources/plain.1KB.txt
resources/plain.10KB.txt
resources/plain.100KB.txt
resources/plain.500KB.txt
];


run_test(
    'continuity', 
    'data/continuity.csv', 
    "type,role,sendMsgFile,Send,Recv,HandshakeCPUTime,CommCPUTime",
    sub { return qq[java -cp httpcore-4.4.16.jar continuity/runTLSEcho.java $_[0] $_[0]] },
);

run_test(
    'xnoise', 
    'data/xnoise.csv', 
    "type,role,sendMsgFile,handshake1_len,handshake2_len,c2sCipher,c2sPlain,s2cCipher,s2cPlain,handshakeCPUTime,commCPUTime",
    sub { return qq[java -cp httpcore-4.4.16.jar:xnoise/noise-java-1.0-SNAPSHOT-xnoise.jar xnoise/runXNoise.java $_[0] $_[0]] },
);

run_test(
    'ukey2', 
    'data/ukey2.csv', 
    "type,role,sendMsgFile,handshake1_len,handshake2_len,handshake3_len,c2sCipher,c2sPlain,s2cCipher,s2cPlain,handshakeCPUTime,commCPUTime", 
    sub { return qq[java -cp httpcore-4.4.16.jar:ukey2/ukey2_java_shadow.jar ukey2/runUkey2.java $_[0] $_[0]] },
);

sub run_cmd {
    my ($cmd, $timeout) = @_;
    my $buffer;
    if( scalar run( command =>  $cmd, 
            verbose => 0,
            buffer  => \$buffer,
            timeout => $timeout )
    ) {
        return $buffer;
    }
}

sub run_test {
    my ($type, $csv, $head,  $cmd_sub) = @_;

    open my $fh_some2, '>', $csv;
    print $fh_some2 "$head\n";
    for my $f (@files){
        my $cmd = $cmd_sub->($f);
        for my $i (1 .. $cnt){
            print "\r$type,$f, $i";
            for( 1 .. $retry){
                my $c = run_cmd($cmd, $timeout);
                if($c and $c!~/Exception/){
                    print $fh_some2 $c;
                    last;
                }
                sleep 1;
            }
        }
    }
    close $fh_some2;

}
