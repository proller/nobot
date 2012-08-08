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
sub dmp (@) { print join ', ', (map { ref $_ ? Data::Dumper->new([$_])->Indent(1)->Pair('=>')->Terse(1)->Sortkeys(1)->Dump() : "'$_'" } @_), "\n"; }
our %config;
$config{root_path} = (($0 =~ m{^(.*(?:^|/))([^/]+)$})[0] || '.');
local %_ = (
  'logfile' => [
    '/tmp/banbot',    #first must be writable
    $config{root_path} . '/banperm',
  ],
  'ipfwtable' => 10,
  'netmin'    => 3,
  'fw'        => 'ipfw -q',
);
$config{$_} = $_{$_} for keys %_;
do 'config.pl';
if ($ENV{'SERVER_PORT'}) {
  my ($ip, $ref) = split /&/, $ENV{'QUERY_STRING'}, 2;
  #if ( $ip eq $ENV{'REMOTE_ADDR'} ) {
  if (open my $f, '>>', ref $config{'logfile'} eq 'ARRAY' ? $config{'logfile'}[0] : $config{'logfile'}) {
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
my (%ban, %net, %cookie, %ip, %stat);
#my $goodua = qr/bot|Yahoo|Rambler|facebook/i;
if (grep { -s $_ } @ARGV) {
  sub resc ($) { local $_ = shift; s{([\(\)\.\[\]\{\}\?])}{\\\1}g; return $_ }
  my @bad_fields = (grep { ref $config{bad}{$_} eq 'HASH' } keys %{$config{bad} || {}});

=no
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
=cut

  my $re = join '|', map { resc $_ } sort (keys %{$config{bad}{ua} || {}}, (map { $config{fast_re_url_bef} . $_ } keys %{$config{bad}{url} || {}}), (keys %{$config{bad}{ref} || {}}));
#$config{fast_re_ref_bef} =  'GET ';
  #warn $re;
  $re = qr/$re/;
#  warn $re;
  #warn Dumper \%goodurl;
  my $stop;
  local $SIG{INT} = sub { ++$stop; };
  for my $logfile (grep { -s $_ } @ARGV) {
    warn "reading $logfile";
    warn("cant open [$logfile]: $!"), next unless open my $f, '<', $logfile;
    while (<$f>) {
      if ($config{fast_re}) {
        my ($ip) = $_ =~ $config{ip_re};    #/^(\S+)/;
        ++$stat{total}{lines};
        ++$ip{$ip}{total} if $ip{$ip};
#dmp $ip;
#dmp $re;
        next if !$ip{$ip} and $_ !~ $re;
      }
#dmp $_ if $_ =~ $re;
#      next if  $_ !~ $re;
      local %_;
#dmp  $_,$ip,$ip{$ip},$re, $_ !~ $re  ;
#dmp  $ip,$ip{$ip}, $_ !~ $re  ;
#m{^(?<ip>\S+) \S+ \S+ \[(?<datetime>\S+) (?<timezone>\S+)\] "(?<metod>\S+) (?<url>\S+) (?<proto>\S+)" (?<status>\d+) (?<size>\d+) "(?<ref>.*?)" "(?<ua>.*?)" (?<domain>\S+) (?<header>\d+) (?<fullsize>\S+) (?<seconds>\d+)};
#m{^(?<ip>\S+) \S+ \S+ \[(?<datetime>\S+) \S+\] "\S+ (?<url>\S+) \S+" \d+ (?<size>\d+) "(?<ref>.*?)" "(?<ua>.*?)" (?<domain>\S+) \d+ \S+ (?<seconds>\d+)};
      if ($config{log_kv}) {
        %_ = map {/([^=]+)=?(.*)?/} split /\t+/;
        ($_{url}) = $_{request} =~ /\S+ (\S+) \S+/ if $_{request} and !$_{url};
        $_{ref} = $_{referer};
#dmp \%_;
      } else {
        $_ =~ $config{log_re};
        %_ = %+;
      }
      next unless $_{ip};
#dmp $config{good}{ua};
      next if $_{ua} =~ $config{good}{ua};
#exit;
      #$ip{$_{ip}}{ua_first} ||= $_{ua};
      my $bad_hit;
      for my $field (@bad_fields) {    #(grep { ref $config{bad}{$_} eq 'HASH' } keys %{$config{bad} || {}}) {
        if ($config{bad}{$field}{$_{$field}}) {
          $ip{$_{ip}}{first}{'bad_' . $field} ||= $_{$field} if $_{$field};
          ++$stat{total}{bad}{$field};
          ++$stat{total}{bad_hits};
          ++$bad_hit;
        } else {
        }
#        ++$stat{fields}{$field}{$_{$field}} if $_{$field};
      }
      next if !$bad_hit and !$ip{$_{ip}};
      ++$stat{total}{bad_hits};
      $ip{$_{ip}}{first}{$_} ||= $_{$_} for grep { length $_{$_} } qw(ua ref url);
      for my $field (@bad_fields) {    #(grep { ref $config{bad}{$_} eq 'HASH' } keys %{$config{bad} || {}}) {
        ++$stat{fields}{$field}{$_{$field}} if $_{$field};
      }
      if ($config{good}{url}{$_{url}}) {
        ++$ip{$_{ip}}{good_url};
        ++$stat{good_url_ua}{$_{ua}};
        ++$ip{$_{ip}}{good_url_ua}{$_{ua}};
      }
      $stat{total}{bad_traff}   += $_{size}    if $_{size};
      $stat{total}{bad_seconds} += $_{seconds} if $_{seconds};
      if ($config{deny_net}) { ($_{net} = $_{ip}) =~ s/\.\d+$//; }
      if ($config{deny_ip}) {
        if ($ip{$_{ip}}{good_url}) {
          delete $net{$_{net}}{$_{ip}};
          delete $ban{$_{ip}};
          #warn "good [ $_{ip} ] ", Dumper  $ip{ $_{ip} };
          ++$ip{$_{ip}}{good_url_skip};
          ++$stat{good_url_skip};
        } else {
          ++$net{$_{net}}{$_{ip}} if $_{net};
          ++$ban{$_{ip}} if $_{ip};
        }
      }
      last if $stop;
    }
  }
  $stat{total}{bad_ips} = scalar keys %ip if %ip;
  $stat{zzz_total} = $stat{total};
#  dmp 'stat:', \%ip, \%stat, \%net, \%ban;
  dmp 'stat:', \%ip, \%stat;
  for my $field (@bad_fields) {
    print "stat by $field:\n";
    for (sort { $stat{fields}{$field}{$b} <=> $stat{fields}{$field}{$a} } keys %{$stat{fields}{$field} || {}}
      ) {
      last if $stat{fields}{$field}{$_} < $config{stat_min};
      print "$stat{fields}{$field}{$_} : $_\n";
#    $stat{fields}
    }
  }
#print map { "$stat{other_url}{$_} : $_\n" } sort    { $stat{other_url}{$b} <=> $stat{other_url}{$a} } keys %{ $stat{other_url} || {} }
#print map { "$stat{domain}{$_} : $_\n" } sort    { $stat{domain}{$b} <=> $stat{domain}{$a} } keys %{ $stat{domain} || {} }
#print map { "$stat{ref}{$_} : $_\n" } sort    { $stat{ref}{$b} <=> $stat{ref}{$a} } keys %{ $stat{ref} || {} }
#exit;
#print Dumper \%stat;
#print Dumper \%ip;
} else {
  for my $logfile (ref $config{'logfile'} eq 'ARRAY' ? @{$config{'logfile'}} : $config{'logfile'}) {
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
        %_ = map { (split /=/, $_, 2) } split /\t/;
        if (keys %_ == 1) {
          ($ip) = keys %_;
          if (!$_{$ip}) {
            delete $_{$ip};
          }
        }
      }
      $_{ip} ||= $ip if $ip;
      next if $_{t} and $_{t} + 86400 * 30 < $time;
      next if $_{ua} =~ $config{good}{ua};
      next if !$_{ip} or $_{ip} =~ /^0|127|255\./;
      #next if $_{ip} =~ /^10\.131\.120\.10?|188\.123\.230\.122$/;    #your safe ip
      #warn ("cookied", $_),
      next if $_{cookie} and $cookie{$_{ip}}++ < 10;
      ($_{net} = $_{ip}) =~ s/\.\d+$//;
      ++$net{$_{net}}{$_{ip}};
      ++$ban{$_{ip}};
    }
  }
}
#print 'ban, net:', Dumper \%ban, \%net;
system "$config{fw} table $config{ipfwtable} flush"
  if grep { $_ eq 'flush' } @ARGV;
if ($config{deny_net}) {
  for (keys %net) {
    next if keys %{$net{$_}} < $config{'netmin'};
    system "$config{fw} table $config{ipfwtable} add $_.0/24";
    delete $ban{$_} for keys %{$net{$_}};
  }
}
if ($config{deny_ip}) {
  for (keys %ban) {
    system "$config{fw} table $config{ipfwtable} add $_";
  }
}
42;
# perltidy -b -i=2 -ce -l=128 -nbbc -sob -otr -sot index.cgi
