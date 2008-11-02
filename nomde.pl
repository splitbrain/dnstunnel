#!/usr/bin/perl

$VERSION = "0.1-splitbrain";

$|=1;

use Fcntl;
use Net::DNS;
use Net::DNS::Nameserver;
use LWP::UserAgent;
use Time::HiRes qw ( usleep gettimeofday );
use MIME::Base64;
use MIME::Base32 qw ( RFC );
use IO::Socket;
use Class::Struct;
use threads;
use threads::shared;
use Thread::Queue;
use Getopt::Long;
use English;


my %opts;
my %mods;

# parse options
$opts{ptrname}  = "127.0.0.1";
$opts{filename} = "nomde.pl";
$opts{forward}  = "sshdns:127.0.0.1:22";
$opts{listen}   = "0.0.0.0";
$opts{verbose}  = 0;
$opts{user}     = 'nobody';
$opts{group}    = 'nobody';
GetOptions(
        "ip=s"      =>  \$opts{ip},
        "ptrname=s" =>  \$opts{ptrname},
        "forward=s" =>  \$opts{forward},
        "listen=s"  =>  \$opts{listen},
        "verbose"   =>  \$opts{verbose},
        "user=s"    =>  \$opts{user},
        "group=s"   =>  \$opts{group}
);
if($ARGV[0]) {
        $opts{localname} = $ARGV[0];
        my @tmp = split('\.', $opts{localname});
        $opts{nameoffset} = $#tmp;
        undef @tmp;
}

# check minimum option or print usage
if(!length($opts{localname}) || !length($opts{ip})){
        print STDERR << "EOD";
nomde $VERSION - Experimental DNS Server, part of OzymanDNS
written by Dan Kaminsky <dan\@doxpara.com>
modified by Andreas Gohr <andi\@splitbrain.org>

Usage:  $opts{filename} <OPTIONS> server.example.com
Options:
    -l [ip address]      Device to listen on (defaults to 0.0.0.0)
    -i [ip address]      IP address to return for all A requests (required)
    -p [name]            Name/IP to return for reverse lookups[ptr]
    -f [name:host:port]  Forward function to address, port
                         (Default:  sshdns:127.0.0.1:22)
    -u [user]            drop privileges to this user
    -g [group]           drop privileges to this group
EOD
        exit 1;
}

struct ( dns_sock => {
        sock     => '$',
        lasttime => '$',
        reader   => '$',
        queue    => '$'
});


struct ( dns_sock_data => {
        data      => '$',
        lasttime  => '$'
});

# set STDIN to nonblock
$flags='';
fcntl(STDIN, F_GETFL, $flags) or die "1\n";
$flags |= O_NONBLOCK;
fcntl(STDIN, F_SETFL, $flags) or die "2\n";

#use strict;
#use warnings;

my $dataclean;

sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost, $header, $packet) = @_;
    my ($rcode, @ans, @auth, @add, $val);

    my @namelist = split(/\./, $qname);
    my @reverselist = reverse(@namelist);
    my $function = $reverselist[$opts{nameoffset}+1];
    my @args = (@reverselist[$opts{nameoffset}+2..$#reverselist]);

    $rcode = "NXDOMAIN";

    if ($qtype eq "AAAA") { $rcode = "NOTIMPL"; goto end;};
    if ($qtype eq "SOA") {
        my $now = gettimeofday(); # yeah that'll give unique serials
        my $name = $opts{localname};
        my ($ttl, $rdata) = (3600, "ns.$name root.$name $now 28800 14400 3600000 0");
        push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
        $rcode = "NOERROR";
        goto end;
    }
    if ($qtype eq "TYPE38") { $rcode = "NOTIMPL"; goto end;};
    if ($qtype eq "A" && $function eq "glance") {
        my $addr = $args[0];
        chomp($addr);
        $addr =~ s/_/\./g;
        $addr =~ s/-/\//g;
        $addr = "http://" . $addr;

        my $ua      = LWP::UserAgent->new;
        my $request = HTTP::Request->new(HEAD => "$addr");
        my $response= $ua->request($request);
        my $modified_time = $response->last_modified;
        my $expires       = $response->expires;
        my $date          = $response->date;

        my $ttl     = $expires - $date;

        my @array = unpack("C*", pack("V", $modified_time));  # will it work?
            my $nsip = join(".", @array);
        if ($ttl < (60*20)) {$ttl = 60*20;}
        push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $nsip");
        $rcode = "NOERROR";
        goto end;
    }

    if ($qtype eq "CNAME") {
        $rcode = "NOERROR";
        goto end;
    }

    if ($qtype eq "PTR") {
        my ($ttl, $rdata) = (0, $opts{ptrname});
        push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
        $rcode = "NOERROR";
    }

    # handling DNS tunneling starts here
    my ($servname, $remotehost, $remoteport) = split(":", $opts{forward});
    if ($function eq "$servname"){
        my $op     = $args[0];
        my $id     = $args[1];
        my ($offset, $nonce) = split("-", $args[2]);

        my $now = gettimeofday();
        if(!$sockclean || $now - $sockclean > 240){
            $sockclean = gettimeofday();
            foreach $scanid (keys %socklist){
                if($now - $socklist{$scanid}->lasttime > 10){
                    $socklist{$scanid}->sock->shutdown(2);
                    delete $socklist{$scanid};
                }
            }
        }

        my $scanid;
        if(!$dataclean || $now - $dataclean > 20){
            $dataclean = gettimeofday();
            foreach $scanid (keys %sockdata) {
                if(defined($sockdata{"$scanid"})&&
                        $now - $sockdata{"$scanid"}->lasttime > 60){
                    delete $sockdata{$scanid};
                }
            }
        }

        if(!exists $socklist{$id}) {
            $socklist{$id}=new dns_sock;
            my $sock = IO::Socket::INET->new(
                    PeerAddr => "$remotehost",
                    PeerPort => "$remoteport",
                    Proto    => "tcp",
                    Type     => SOCK_STREAM,
                    Blocking => 1);# or die "couldn't spawn socket\n";
            $socklist{$id}->queue(Thread::Queue->new);
            $socklist{$id}->sock($sock);
            $socklist{$id}->reader(threads->new(\&reader, $socklist{$id}->sock, $socklist{$id}->queue));
        }

        $socklist{$id}->lasttime($now);
        my $sock = $socklist{$id}->sock;

        my $sockdata_is_fresh=0;
        if(!exists $sockdata{$op,$offset,$id}) {
            $sockdata{$op,$offset,$id} = new dns_sock_data;
            $sockdata{$op,$offset,$id}->lasttime($now);
            $sockdata_is_fresh=1;
        }

        my $data = $sockdata{$op,$offset,$id}->data;
        if($op eq "up" && $qtype eq "A"){
            my $size=0;
            $data = uc join("", reverse(@args[3..$#args]));
            $data = MIME::Base32::decode($data);

            if($sockdata_is_fresh){
                while($size != length($data)) {
                    my $outdata;
                    $outdata = substr($data, $size);
                    $size += syswrite($sock, $outdata, length($data)-$size);
                    if($size != length($data)){usleep (100 * 1000);}
                }
                $data="1"; #for now, we don't store incoming data
            }
            $sockdata{$op,$offset,$id}->data($data);
            my $reply = "$size.0.0.0";
            my $ttl  = 0;
            push @ans, Net::DNS::RR->new("$qname $ttl $qclass A $reply");
            $rcode = "NOERROR";

            goto end;
        }

        sub reader {
            my @args = @_;
            my $sock = $args[0];
            my $queue= $args[1];
            my $data;

            while(1){
                if($queue->pending < 32) {
                    sysread($sock, $data, 220);
                    if(length($data)) {$queue->enqueue($data);}
                    usleep (50 * 1000 / 10);
                }
            }
        }

        if($op eq "down"){ #intentionally not txt checking
            if($sockdata_is_fresh || length($data)==0) {
                $data = $socklist{$id}->queue->dequeue_nb;
            }
            $sockdata{$op,$offset,$id}->data($data);
            my $data1  = substr($data, 0, 110);
            my $data2  = substr($data, 110, 110);
            my $txt1 = encode_base64($data1);
            my $txt2 = encode_base64($data2);
            my $x    = $socklist{$id}->queue->pending;

            push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype \"$txt1\" \"$txt2\"");
            push @add, Net::DNS::RR->new("pending.$qname $ttl $qclass A $x.0.0.0");
            $rcode = "NOERROR";
            goto end;
        }
    }

    if ($qtype eq "TXT") {
        $val = localtime();
        chomp $val;
        $val = "Hi:  $val";
        my ($ttl, $rdata) = (0, $val);
        push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype \"$rdata\"");
        $rcode = "NOERROR";
        goto end;
    }

    if ($qtype eq "NS") {
        if($function ne "ns"){
            my ($ttl, $rdata) = (3600, "ns.$opts{localname}");
            push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
            push @add, Net::DNS::RR->new("$rdata $ttl $qclass $qtype $opts{ip}");
        }
        $rcode = "NOERROR";
        goto end;
    }


    if ($qtype eq "A") {
        my ($ttl, $rdata) = (3600, $opts{ip});
        push @ans, Net::DNS::RR->new("$qname $ttl $qclass $qtype $rdata");
        $rcode = "NOERROR";
        goto end;
    }

end:
    if($opts{verbose}){
        my ($element, $name);
        print "\n";
        foreach $element (@ans, @auth, @add) {
            $name = $element->string;
            chomp $name;
            print $name, "\n";
        }
    }

    # mark the answer as authoritive (by setting the 'aa' flag
    my @response = ($rcode, \@ans, \@auth, \@add, { aa => 1 });
    return @response;
}


# note that this socket is blocking -- WAY harder to do nonblocking with
# callbacks (need fork/ipc).
my %socklist : shared;
my %sockdata;

# check users
die "You need to be root to run this on port 53\n" if($>);
$dropuid = getpwnam($opts{user});
die("User $opts{user} does not exist") if(!$dropuid);
$dropgid = getgrnam($opts{group});
die("Group $opts{group} does not exist") if(!$dropgid);

# open socket
my $ns = Net::DNS::Nameserver->new(
    LocalAddr    => $opts{listen},
    LocalPort    => 53,
    ReplyHandler => \&reply_handler,
    Verbose      => $opts{verbose},
) || die "couldn't create nameserver object\n";

# drop privileges
print "Dropping privileges to UID=$dropuid GID=$dropgid\n" if($opts{verbose});
( $(, $) ) = ("$dropgid $dropgid","$dropgid $dropgid");
( $<, $> ) = ($dropuid, $dropuid);
( $<, $> ) = ($dropuid, $dropuid);

# run
$ns->main_loop;

