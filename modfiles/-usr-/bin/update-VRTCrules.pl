#!/usr/bin/perl
#
# VRT Community rules updater program for snort
#
# modified from the update-snortrules.pl written by s-t-p (aka Stan Prescott)
# which was taken from the ids.cgi in SmoothWall 3.0 (c) The SmoothWall Team
#
# provided by wkitty42 for use under the GPL agreement
#
# updated 2012 Nov 2 -wkitty42
#   don't delete the old log file... keep it and append to it for history...
#
# updated 2010 Oct 10 - wkitty42
#   fixed snort version detection (again)
#
# updated 2009 Nov 19 - wkitty42
#   adjusted to pull the emergingthreats rulesets and place them in the existing ${swroot}/snort/rules directory
#   creates and maintains /var/log/snort/et-autoupdate.log
#
# updated 2008 June 6 - wkitty42
#   fixed ruleage file updating - when this updater runs, ruleage will contain the time and date of the update
#   fixed ownership of the ruleage file so that the GUI can read it
#   added logging to /var/log/snort/autoupdate.log  (as root:root)
#   we do not use STDERR output any more.
#   moved EXIT to the bottom so that we do not run thru all the motions if the oinkcode or snort_enabled are wrong or off
#   we redirect oinkmaster's output in the same way that we get the snort version from snort ;)
#     this allows us to parse the output do determine the update failure reason
#   we now log the ERROR 403 update failure reason from oinkmaster (ie: try your update after blah time. it is now foo time.)
#
#

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );
use Cwd;
use File::Find;
@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
@weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);

my $GAR_Home_dir = "${swroot}/mods/GAR";
my $VRTC_ruleage = "${swroot}/snort/VRTC_ruleage";
my $logfile = "/var/log/snort/autoupdate-VRTC.log";
#if (-e $logfile) { unlink $logfile };
#open STDERR, ">>$logfile";
open STDOUT, ">>$logfile";
my $tmpdir = "/tmp/VRTC-tmp";

sub write_log {
  my ($message) = @_;
  ($wkday,$month,$day,$time,$year) = split(/\s+/, localtime);
  if ($day < 10)
  {
    $day = " $day";
  }
  print "$month $day $time $message";
}

sub get_the_time {
    ($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek, $dayOfYear, $daylightSavings) = localtime();
    $year = 1900 + $yearOffset;
    $theTime = "$weekDays[$dayOfWeek] $months[$month]";
    if ($dayOfMonth < 10) {
	$theTime = "$theTime 0$dayOfMonth $year";
    } else {
	$theTime = "$theTime $dayOfMonth $year";
    }
    if ($hour < 10) {
	$theTime = "$theTime 0$hour";
    } else {
	$theTime = "$theTime $hour";
    }
    if ($minute < 10) {
	$theTime = "$theTime:0$minute";
    } else {
	$theTime = "$theTime:$minute";
    }
    if ($second < 10) {
	$theTime = "$theTime:0$second";
    } else {
	$theTime = "$theTime:$second";
    }
}

sub get_newest {
    my $dir = shift;
    -d $dir or die "'$dir' is not a directory...\n";
    my %files;
    File::Find::find (
	sub {
	    my $name = $File::Find::name;
	    # we only want the community.rules file
	    if ($name =~ /community\.rules/) {
		$files{$name} = (stat $name)[9] if -f $name;
	    }
	}, $dir
    );
    ( sort { $files{$a} <=> $files{$b} } keys %files )[-1];
}

sub do_ruleage_closeout {
    my ${newest_file} = 'unknown';
    &write_log("Updating ${VRTC_ruleage} file\n");
    &write_log("Collecting current update time:\n");
    &get_the_time;
    &write_log("  $theTime\n");
    &write_log("Storing update time:\n");
    &write_log("  $theTime\n");
#    unlink "${VRTC_ruleage}";
    open (FILE, ">${VRTC_ruleage}");
    print FILE "$theTime";
    close (FILE);
    &write_log("Locating newest VRTC rules file:\n");
    ${newest_file} = get_newest("${swroot}/snort/rules");
    &write_log("  ${newest_file}\n");
    &write_log("Collecting ${newest_file}'s time stamps:\n");
    ($a_stamp, $m_stamp) = (stat ${newest_file})[8,9];
    &write_log("  $a_stamp  $m_stamp\n");
    &write_log("  " . scalar(localtime(${a_stamp})) . "\n");
    &write_log("  " . scalar(localtime(${m_stamp})) . "\n");
    &write_log("Storing time stamps to ${VRTC_ruleage}\n");
    utime $a_stamp, $m_stamp, ${VRTC_ruleage};
#    $e_code = $? >> 8;
#    $s_code = $? >> 127;
#    $c_code = $? >> 128;
#    printf( "DEBUG: %d: %s\n", $e_code, $e_code );
#    printf( "DEBUG: %d: %s\n", $s_code, $s_code );
#    printf( "DEBUG: %d: %s\n", $c_code, $c_code );
#    printf( "DEBUG: %d: %s\n", $!, $! );
    &write_log("Verifying ${VRTC_ruleage}'s time stamps:\n");
    undef $a_stamp, $m_stamp;
    ($a_stamp, $m_stamp) = (stat ${VRTC_ruleage})[8,9];
    &write_log("  $a_stamp  $m_stamp\n");
    &write_log("  " . scalar(localtime(${a_stamp})) . "\n");
    &write_log("  " . scalar(localtime(${m_stamp})) . "\n");
    &write_log("Setting ${VRTC_ruleage} ownership to nobody:nobody\n");
    system("/bin/chown nobody:nobody ${VRTC_ruleage}");
}

&write_log("-------------------------------------------------------------------------------\n");
&write_log("VRTC SNORT Rules Auto-Updater - starting\n");

&write_log("Loading SNORT settings\n");
my %snortsettings;
&readhash("${swroot}/snort/settings", \%snortsettings);

my $errormessage = 'start';

if ($snortsettings{'ENABLE_SNORT'} eq 'off') {
    &write_log("SNORT is not enabled.");
    &write_log("SNORT should be enabled to make running this worth while...\n");
    &write_log("Continuing anyway...\n");
}

#start snort version query
open(MY_INPUT,"/usr/bin/snort -V 2>&1 |");
while(<MY_INPUT>) {
    chomp;
    if (/Version\s+(.*)/) {
       ($display_version, $sub1, $sub2, $sub3) = split(/ /,$1);
       $snort_version = $display_version;
# VRTC bases snort rules on X.Y.Z versioning
#       $snort_version =~ s/\.//g;
       $display_version .= " $sub1 $sub2 $sub3";
    }
}
close(MY_INPUT);
# VRTC bases snort rules on X.Y.Z versioning
# so pull first characters up to 5 of version 
$snort_version = substr $snort_version, 0, 5;
# now make sure string is 5 charaters long
while (length($snort_version) < 5) {
    $snort_version .= '.0'; }
&write_log("Working with snort $display_version - [$snort_version]\n");
#if ($snortsettings{'SUBSCRIBER'} eq 'on') {
#    ${snort_version} = ${snort_version} . '_s';
#    &write_log("We are a paying subscriber for the Sourcefile VRT rules sets\n");
#}
# end snort version query

my $curdir = getcwd;
my $url = 'https://s3.amazonaws.com/snort-org/www/rules/community/community-rules.tar.gz';

&write_log("Creating tmp directory $tmpdir\n");
unless (mkdir $tmpdir) {
  &write_log("Unable to create directory $tmpdir\n");
  die "Unable to create directory $tmpdir";
}

&write_log("Changing current directory to $tmpdir\n");
chdir "$tmpdir";
my $id = 0;
while ($errormessage) {
    $id++;
    &write_log("Executing wget\n");
    open(FD, "/usr/bin/wget $url 2>&1 |");
    $errormessage = '';
    while(<FD>) {
	chomp;
	if (/ERROR 403:\s+(.*)/i) {
	    $errormessage = $1;
	}
	if (/ERROR 404:\s+(.*)/i) {
	    $errormessage = $1;
	}
	# uncomment the next line to log the output from oinkmaster
	&write_log("        wget: $_\n");
    }
    close(FD);
    if ($?) {
	&write_log("Attempt $id: $tr{'unable to fetch rules'}\n");
	&write_log("Reason: $errormessage\n");
	if (($errormessage eq "Not Found.") or ($errormessage eq "Forbidden.")) {
	    &write_log("Will not try again...\n");
	    last;
	} else {
	    if ($errormessage and $id < 7) {
		&write_log("Will try again in 5 minutes...\n");
		sleep 300;
	    }
	}
    } else {

## untar community-rules file and copy the rules to the snort/rules directory
    &write_log("Executing tar\n");
    open(FD, "/usr/bin/tar -zxvf community-rules.tar.gz 2>&1 |");
    $errormessage = '';
    while(<FD>) {
	chomp;
	if (/ERROR 403:\s+(.*)/i) {
	    $errormessage = $1;
	}
	if (/ERROR 404:\s+(.*)/i) {
	    $errormessage = $1;
	}
	# uncomment the next line to log the output from oinkmaster
	&write_log("         tar: $_\n");
    }
    close(FD);

    &write_log("Changing current directory to ${swroot}/snort/\n");
    chdir "${swroot}/snort/";

    $url = "dir://$tmpdir/community-rules";
    &write_log("Executing oinkmaster.pl\n");
    open(FD, "/usr/bin/oinkmaster.pl -C /usr/lib/smoothwall/oinkmaster.conf -o rules -u $url 2>&1 |");
    while(<FD>) {
	chomp;
	if (/ERROR 403:\s+(.*)/i) {
	    $errormessage = $1;
	}
	if (/ERROR 404:\s+(.*)/i) {
	    $errormessage = $1;
	}
	# uncomment the next line to log the output from oinkmaster
	&write_log("  oinkmaster: $_\n");
    }
    &write_log("Removing tmp directory $tmpdir\n");
    open(FD, "/bin/rm -frv $tmpdir 2>&1 |");
    while(<FD>) {
	chomp;
	if (/ERROR 403:\s+(.*)/i) {
	    $errormessage = $1;
	}
	if (/ERROR 404:\s+(.*)/i) {
	    $errormessage = $1;
	}
	# uncomment the next line to log the output from oinkmaster
	&write_log("          rm: $_\n");
    }
        
	&do_ruleage_closeout;
	
	&write_log("Updating sid-msg.map\n");
	system("$GAR_Home_dir/usr/bin/smoothwall/make-sidmap.pl");
	&write_log("Setting rules ownership to nobody:nobody\n");
	system("/bin/chown nobody:nobody ${swroot}/snort/rules/community.rules");
### commented out next 6 lines because the ET run will restart snort for us
#	&write_log("Restarting snort\n");
#	my $success = message('snortrestart');
#	if (not defined $success) {
#	    $errormessage = 'Unable to restart snort - see /var/log/messages for details'; }
#	if ($errormessage) {
#	    &write_log("$errormessage\n"); }
	$errormessage = '';
    }
}

chdir $curdir;

EXIT:

&write_log("VRTC SNORT Rules Auto-Updater - complete\n");
