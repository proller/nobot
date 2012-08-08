#!/usr/bin/perl
# $Id$

=USAGE

perl index.cgi
 process /tmp/banbot banperm

perl index.cgi /path/to/access.log
 process access.log

run from web server:
 add line to /tmp/banbot



=howto

touch /tmp/banbot && chmod a+rw /tmp/banbot

crontab:
 */5     *    *      *      *    root /usr/local/www/nobot/index.cgi

ipfw:
 ipfw add 7 deny ip from table\(10\) to me 80

script:
 print qq{<a rel="nofollow" id="banbot" style="position:absolute;top:-100px;left:-100px;display:none;background-color:#ffffff;color:#ffffff;" href="/nobot/?$ENV{'REMOTE_ADDR'}">l</a><script>document.getElementById('banbot').outerHTML='';</script>};

robots.txt:
 User-agent: *
 Disallow: /nobot/


to ban security hole scanners:
 echo "Include /usr/local/www/nobot/defence.conf" >> /usr/local/etc/apache22/httpd.conf
OR
 ln -s /usr/local/www/nobot/defence.conf /usr/local/etc/apache22/Includes
and include defence.conf in your httpd.conf

=cut



use strict;
use Data::Dumper;
$Data::Dumper::Sortkeys = $Data::Dumper::Useqq = $Data::Dumper::Indent = 1;
my %config = (
  'logfile' => [
    '/tmp/banbot',    #first must be writable
    ( ( $0 =~ m{^(.*(?:^|/))([^/]+)$} )[0] || '.' ) . '/banperm',
  ],
  'ipfwtable' => 10,
  'netmin'    => 3,
  'fw'        => 'ipfw -q',
);
if ( $ENV{'SERVER_PORT'} ) {
  my ( $ip, $ref ) = split /&/, $ENV{'QUERY_STRING'}, 2;
  #if ( $ip eq $ENV{'REMOTE_ADDR'} ) {
  if ( open my $f, '>>', ref $config{'logfile'} eq 'ARRAY' ? $config{'logfile'}[0] : $config{'logfile'} ) {
    local $, = "\t";
    print $f "t=" . int(time), "ip=" . $ENV{'REMOTE_ADDR'},
      #"time=" . scalar localtime,
      "ipp=" . $ip,
      "ua=" . $ENV{'HTTP_USER_AGENT'}, "host=" . $ENV{'HTTP_HOST'},
      "ref=" . $ENV{'HTTP_REFERER'},
      "refref=" . $ref,
      "cookie=" . $ENV{'HTTP_COOKIE'},
      "uri=" . $ENV{'REQUEST_URI'},
      #'dmp='.Data::Dumper->new([\%ENV])->Indent(0)->Terse(1)->Dump(),
      "\n";
    #close $f;
  } else {
    warn "cant open file [$config{'logfile'}]: $!";
  }
  print "\n\n.";    #. Dumper \%ENV;
                    #}
  exit;
}    # els
my ( %ban, %net, %cookie, %ip, %stat );
my $goodua = qr/bot|Yahoo|Rambler|facebook/i;
if ( grep { -s $_ } @ARGV ) {
  sub resc ($) { local $_ = shift; s{([\(\)\.\[\]\{\}\?])}{\\\1}g; return $_ }
  my %badua = map { $_ => 1 } (
    'Mozilla/4.0 (compatible; MSIE 5.0; Windows 3.1)',
    'Mozilla/1.22 (compatible; MSIE 2.0; Windows 95)',
    'Mozilla/1.22 (compatible; MSIE 2.0d; Windows NT)',
    'Mozilla/0.6 Beta (Windows)',
    'Mozilla/3.0 (x86 [en] Windows NT 5.1; Sun)'
  );
  #my $badua = join '|', map { resc $_ } sort keys %badua;
  #$badua = qr/ "(?:$badua)" /;
  my %goodurl = map { $_ => 1 } qw(/i/logo.png /lib/lib.js /base.css);
  my %badurl  = map { $_ => 1 } qw(
    /?q=addurl
    /?q=VMWARE.KMS.FOR.OFF-ONLINE.ACTIVATION.WIN7.PRO-ENT.VOL.EDITION-RU_BOARD
    /?form=1&q=VMWARE.KMS.FOR.OFF-ONLINE.ACTIVATION.WIN7.PRO-ENT.VOL.EDITION-RU_BOARD
    /?lang=ru&q=VMWARE.KMS.FOR.OFF-ONLINE.ACTIVATION.WIN7.PRO-ENT.VOL.EDITION-RU_BOARD
    /?lang=en&q=VMWARE.KMS.FOR.OFF-ONLINE.ACTIVATION.WIN7.PRO-ENT.VOL.EDITION-RU_BOARD
    /?form=1&lang=en&q=VMWARE.KMS.FOR.OFF-ONLINE.ACTIVATION.WIN7.PRO-ENT.VOL.EDITION-RU_BOARD
    /?form=1&lang=ru&q=VMWARE.KMS.FOR.OFF-ONLINE.ACTIVATION.WIN7.PRO-ENT.VOL.EDITION-RU_BOARD
  );
  $config{ref_bad} = {map { $_ => 1 }qw( http://alawarstore.com http://diazepampill.com http://gotovoe-dz.ru/publ/ http://gotovoe-dz.ru) };
  my $re = join '|', map { resc $_ } sort ( keys %badua, keys %badurl, keys %{$config{ref_bad}||{}} );
  #warn $re;
  $re = qr/$re/;
  #warn $re;
  #warn Dumper \%goodurl;
  for my $logfile ( grep { -s $_ } @ARGV ) {
#warn $logfile;
    warn("cant open [$logfile]: $!"), next unless open my $f, '<', $logfile;
    while (<$f>) {
      my ($ip) = /^(\S+)/;
      ++$ip{$ip}{total} if $ip{$ip};
      next if !$ip{$ip} and $_ !~ $re;
#print $_;
#m{^(?<ip>\S+) \S+ \S+ \[(?<datetime>\S+) (?<timezone>\S+)\] "(?<metod>\S+) (?<url>\S+) (?<proto>\S+)" (?<status>\d+) (?<size>\d+) "(?<ref>.*?)" "(?<ua>.*?)" (?<domain>\S+) (?<header>\d+) (?<fullsize>\S+) (?<seconds>\d+)};
m{^(?<ip>\S+) \S+ \S+ \[(?<datetime>\S+) \S+\] "\S+ (?<url>\S+) \S+" \d+ (?<size>\d+) "(?<ref>.*?)" "(?<ua>.*?)" (?<domain>\S+) \d+ \S+ (?<seconds>\d+)};
      %_ = %+;
      next unless $_{ip};
      next if $_{ua} =~ $goodua;
      $ip{ $_{ip} }{ua_first} ||= $_{ua};
      if ( $badua{ $_{ua} } ) {
        ++$ip{ $_{ip} }{bad_ua};
        $ip{ $_{ip} }{bad_ua_first} ||= $_{ua};
        ++$stat{badua_total};
      } else {
        ++$stat{other_ua}{ $_{ua} };
        ++$stat{other_ua_total};
      }
      if ( $badurl{ $_{url} } ) {
        ++$ip{ $_{ip} }{bad_url};
        $ip{ $_{ip} }{bad_url_first} ||= $_{url};
      } else {
        #++$ip{ $_{ip} }{other_url}{$_{url}};
        ++$stat{other_url}{ $_{url} };
        ++$stat{other_url_total};
      }
      if ( $config{ref_bad}{ $_{ref} } ) {
        ++$ip{ $_{ip} }{ref_bad};
        $ip{ $_{ip} }{ref_bad_first} ||= $_{ref};
      }
      #! ++$stat{domain}{ $_{domain} } if $_{domain};
       ++$stat{ref}{ $_{ref} } if $_{ref};
      #warn $_{url};
      #warn Dumper \%_ if $goodurl{$_{url}};
      if ( $goodurl{ $_{url} } ) {
        ++$ip{ $_{ip} }{good_url};
        ++$stat{good_url_ua}{ $_{ua} };
        ++$ip{ $_{ip} }{good_url_ua}{ $_{ua} };
      }
      $stat{bad_traff} += $_{size};
      $stat{bad_sec}   += $_{seconds};
      ( $_{net} = $_{ip} ) =~ s/\.\d+$//;
      if ( $ip{ $_{ip} }{good_url} ) {
        delete $net{ $_{net} }{ $_{ip} };
        delete $ban{ $_{ip} };
        #warn "good [ $_{ip} ] ", Dumper  $ip{ $_{ip} };
        ++$ip{ $_{ip} }{good_url_skip};
        ++$stat{good_url_skip};
      } else {
        ++$net{ $_{net} }{ $_{ip} } if $_{net};
        ++$ban{ $_{ip} } if $_{ip};
      }
    }
  }
  $stat{bad_ip} = scalar keys %ip if %ip;
print Dumper \%ip, \%stat, \%net, \%ban;
#print map { "$stat{other_url}{$_} : $_\n" } sort    { $stat{other_url}{$b} <=> $stat{other_url}{$a} } keys %{ $stat{other_url} || {} }
#print map { "$stat{domain}{$_} : $_\n" } sort    { $stat{domain}{$b} <=> $stat{domain}{$a} } keys %{ $stat{domain} || {} }
#print map { "$stat{ref}{$_} : $_\n" } sort    { $stat{ref}{$b} <=> $stat{ref}{$a} } keys %{ $stat{ref} || {} }
#exit;
#print Dumper \%stat;
#print Dumper \%ip;
} else {
  for my $logfile ( ref $config{'logfile'} eq 'ARRAY' ? @{ $config{'logfile'} } : $config{'logfile'} ) {
    warn("cant open [$logfile]: $!"), next unless open my $f, '<', $logfile;
    my $time = time;
    while (<$f>) {
      local %_;
      next if $_ =~ /^\s*(?:#|$)/;
      chomp;
      my $ip;
      if (s/^\s*((?:\d+\.?)+)\s+//) {
        $ip = $1;
      } else {
        %_ = map { ( split /=/, $_, 2 ) } split /\t/;
        if ( keys %_ == 1 ) {
          ($ip) = keys %_;
          if ( !$_{$ip} ) {
            delete $_{$ip};
          }
        }
      }
      $_{ip} ||= $ip if $ip;
      next if $_{t} and $_{t} + 86400 * 30 < $time;
      next if $_{ua} =~ $goodua;
      next if !$_{ip} or $_{ip} =~ /^0|127|255\./;
      #next if $_{ip} =~ /^10\.131\.120\.10?|188\.123\.230\.122$/;    #your safe ip
      #warn ("cookied", $_),
      next if $_{cookie} and $cookie{ $_{ip} }++ < 10;
      ( $_{net} = $_{ip} ) =~ s/\.\d+$//;
      ++$net{ $_{net} }{ $_{ip} };
      ++$ban{ $_{ip} };
    }
  }
}
#print 'ban, net:', Dumper \%ban, \%net;
system "$config{fw} table $config{ipfwtable} flush"
  if grep { $_ eq 'flush' } @ARGV;
for ( keys %net ) {
  next if keys %{ $net{$_} } < $config{'netmin'};
  system "$config{fw} table $config{ipfwtable} add $_.0/24";
  delete $ban{$_} for keys %{ $net{$_} };
}
for ( keys %ban ) {
  system "$config{fw} table $config{ipfwtable} add $_";
}
42;
# perltidy -b -i=2 -ce -l=128 -nbbc -sob -otr -sot index.cgi
