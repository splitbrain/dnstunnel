#!/usr/bin/perl

$VERSION="0.1";

use Fcntl;
use Net::DNS;
use MIME::Base64;
use MIME::Base32 qw ( RFC );
use Time::HiRes qw (usleep gettimeofday );
use Getopt::Long;
use threads;
use Thread::Queue;


# hardcoded destinations
my $verbose=0;
my $resolver, $upresolver, $downresolver;
undef $resolver, $upresolver, $downresolver;
my $min_sleep = $sleep = 100;
my $mode = "failover";

my $extension;
undef $extension;

my $persistence = 5;
undef $file, $resolver;

my $infile = STDIN;
my $outfile = STDOUT;
GetOptions(
	   "file=s"     => \$file,
	   "resolver=s" => \$resolver,
	   "upresolver=s" => \$upresolver,
	   "downresolver=s"=>\$downresolver,
	   "minsleep=i" => \$minsleep,
	   "verbose" => \$verbose,
	   "persistence" => \$persistence,
	   "cyclemode=s" => \$mode);

if(length($ARGV[0])) { $extension = $ARGV[0];}

if(!defined($extension)){
    print STDERR <<"EOD";
droute $VERSION:    Reliable DNS Transport for standard input/output
Component of:  OzymanDNS $VERSION      Dan Kaminsky(dan\@doxpara.com)
     Example:  ssh -C -o ProxyCommand="./droute -s tun.server.com" user\@host
     Options:  -r [nameservers]:  Specify nameservers to lookup against
               -m [minsleep]   :  Specify minimum sleep delay between probes
               -c [mode]       :  DNS Server Selection Model *
               -p [rounds]     :  Number of requests before changing server (5)
 Experiments:  -u/-d [ns'ers]  :  Upstream/Downstream Servers
               -f [file]       :  (Possibly large) list of DNS servers
*      Modes:  -c failover     :  Move to next server only when one fails
               -c circle       :  Move to next server with each packet group
               -c random       :  Move to random server with each packet group
EOD
   exit 1;
}
if ($mode ne "circle" && $mode ne "random") {$mode = "failover";}
if(defined($resolver)) {$upresolver = $downresolver = $resolver;}

# set STDIN to nonblock
$flags='';
fcntl($infile, F_GETFL, $flags) or die "1\n";
$flags |= O_NONBLOCK;
fcntl($infile, F_SETFL, $flags) or die "2\n";

# remove \n handling
binmode $infile;
binmode $outfile;

# conf downstream DNS
my $res_down = Net::DNS::Resolver->new;
$res_down->retry(0);
$res_down->retrans(1);
if(defined $downresolver) {
   @downlist = split(",", $downresolver); 
} else {@downlist = $res_down->nameserver;}

#$res_down->persistent_udp(0);

#conf upstream DNS
my $res_up = Net::DNS::Resolver->new;
$res_up->retry(0);
$res_up->retrans(1);
if(defined $upresolver) {
   @uplist = split(",", $upresolver); 
} else {@uplist = $res_up->nameserver;}

if(defined $file){
   open(FILE, "$file");
   @dnsservs = <FILE>;
   close FILE;
   @downlist = (@downlist, @dnsservs);
   @uplist   = (@uplist,   reverse (@dnsservs));
}
$res_down->nameserver(join(" ", @downlist));
$res_up->nameserver(join(" ", @uplist));

if($verbose) {print STDERR "Resolving through:  \n  UP: ", join(", ", $res_up->nameserver), "\n  DN: ", join(", ", $res_down->nameserver), "\n";}


# hardcoded session ID -- should be B32'd and increased
my $id = int rand(65536);
my $sum = 0;

my $sum_up=0;
my $size_up=0;

my $data_up;

my $sent_up = $sent_down = $do_send_up = 0;
my $max_sleep = 4000;
my $then = 0;


my $payload;

my $upstate = "NEED_DATA";
my $up_sock;
my $up_sent_time;
my $down_sent_time;

my $down_sock;
my $downstate = "NEED_DATA";

my @txt, $data, $val;
my $hop_up=int rand($#uplist);
my $hop_down=int rand($#downlist);;
$val=0;
$throws_up = $throws_down = 0;



$read_queue  = Thread::Queue->new;
$read_thread = threads->new(\&reader);
sub reader {
   while(1){
      if($read_queue->pending < 32){
         my $data="";
         $error=sysread(STDIN, $data, 110);
         if(length($data)){ $read_queue->enqueue($data);}
         if(undef $error) {exit(1);}
      }
      usleep(50 * 1000);
   }
}

while(1)
{
	# per packet nonce to evade min-ttl's
	my $nonce=int rand(65536);
	if($mode eq "circle") {
	   if(!$throws_up)  { $throws_up = $persistence; $hop_up++;
	       $res_up->nameserver($uplist[$hop_up % ($#uplist+1)]);}
	   if(!$throws_down){ $throws_down = $persistence; $hop_down++;
	       $res_down->nameserver($downlist[$hop_down % ($#downlist+1)]);}
	}
	if($mode eq "random") {
           if(!$throws_up)   {$throws_up = $persistence; $res_up->nameserver($uplist[rand(($#uplist+1))]);}
           if(!$throws_down) {$throws_down = $persistence; $res_down->nameserver($downlist[rand(($#downlist+1))]);}
        }
        if($mode eq "failover") {
	   $res_up->nameserver($uplist[$hop_up % ($#uplist+1)]);
           $res_down->nameserver($downlist[$hop_down % ($#downlist+1)]);
	}

	if($downstate eq "NEED_DATA"){
	   undef $down_sock;
	   $down_sock = $res_down->bgsend("$sum-$nonce.id-$id.down.$extension", "TXT");
	   $down_sent_time = gettimeofday();
	   if(defined $down_sock) { $downstate = "WAIT_FOR_REPLY"; }
	}

	if($downstate eq "WAIT_FOR_REPLY"){
	   if($res_down->bgisready($down_sock)) { $downstate = "GOT_REPLY"; }
	   if(gettimeofday() - $down_sent_time > 2) {
	      undef $down_sock;
	      $throws_down=0;
	      if($mode eq "failover") {$hop_up++; $hop_down++;}
	      $downstate = "NEED_DATA";
	   }
	}

	if($downstate eq "GOT_REPLY"){
	   $throws_down--;
	   my $reply = $res_down->bgread($down_sock);
	   undef $down_sock;
	   $data="";
	   $val=0;
	   if($reply){
	     foreach $rr (grep { $_->type eq 'TXT' } $reply->answer) {
	       # note -- TXT records support multiple text regions.  These are not reordered.
	       @txt = $rr->char_str_list();
	       foreach $textdata (@txt) { $data = $data . decode_base64($textdata); } 
	     }
	     if(length($data)){
		$sleep = $min_sleep;
	        $downstate = "WRITE_TO_STDOUT";
	     } else {
	        $sleep*=3;
		if($sleep > $max_sleep) { $sleep = $max_sleep; }
	        $downstate = "CHECK_TIME";
	     }
	   }
	}

	if($downstate eq "WRITE_TO_STDOUT"){
	  my $outdata = substr($data, $val);
	  $val+=syswrite(STDOUT, $outdata, length($data)-$val);
	  if($val == length($data)){
	    $sum+=$val;
	    $downstate = "CHECK_TIME";
	  }
	}

	if($downstate eq "CHECK_TIME"){
	   $diff = gettimeofday() - $down_sent_time;
	   if($diff*1000 > $sleep) { $downstate = "NEED_DATA"; }
	}
	   
	up:
 


	if($upstate eq "NEED_DATA"){
	   if($read_queue->pending){
	      $upstate = "GOT_DATA";
	   }
	}

	if($upstate eq "GOT_DATA"){
	  my $temp_payload;
	  my $data = $read_queue->dequeue_nb;
	  if(defined $data){
	     $temp_payload = lc MIME::Base32::encode($data);
	     $temp_payload =~s/(.{60})/$1\./g;
	     $temp_payload =~s/\.\././g;
	     $payload = "$temp_payload.$nonce-$sum_up.id-$id.up.$extension";
	     $upstate = "SEND_DATA";
	  }
	}

	if($upstate eq "SEND_DATA")
	{
	   undef $up_sock;
	   $up_sock = $res_up->bgsend("$payload", "A");
	   $up_sent_time = gettimeofday();
	   if(defined $up_sock) { $upstate = "WAIT_FOR_REPLY"; }
	}

	if($upstate eq "WAIT_FOR_REPLY"){
	   if($res_up->bgisready($up_sock)){
	      $upstate = "GOT_REPLY";
	   }
	   if(gettimeofday() - $up_sent_time > 4.0){
	      undef $up_sock;
	      $throws_up=0;
	      if($mode eq "failover") {$hop_up++;}
	      $upstate = "SEND_DATA";
	   }
	}

	if($upstate eq "GOT_REPLY")
	{
	   $throws_up--;
	   my $reply_up = $res_up->bgread($up_sock);
	   undef $up_sock;
	   if($reply_up && ($reply_up->header->ancount > 0)) {
	      $upstate = "NEED_DATA";
	      $sleep = $min_sleep;
	   } else {
	      $upstate = "SEND_DATA";
	   }
	}

	#print STDERR "$upstate $downstate\n";

	usleep($min_sleep * 1000 / 10);
	#usleep ($sleep * 1000);
	#usleep(100 * 1000);
}

