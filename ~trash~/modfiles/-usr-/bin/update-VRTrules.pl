#!/usr/bin/perl
#
# Snort rules updater program
#
# Taken from the ids.cgi in SmoothWall 3.0 (c) The SmoothWall Team
#
# additional code to read in oink code provided by flatline
#
# provided by Stan Prescott for use under the GPL agreement
#
# updated 2012 Nov 2 - wkitty42
#   do not delete old log file... keep it for history...
#
# updated date unknown - wkitty42
#   if the VRT 15 minute limit is in place, just wait for 20 and try then...
#     we used to be told what time the limit would be lifted and could set
#     our retry time for a minute or so after that but when they moved their
#     stuff to the cloud, they changed their message and the time is not
#     given any more. so now we just wait for 20 minutes to pass and then
#     try again. we make the attempt 6 times so that give us 2 hours which
#     should be enough time...
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

my ${GAR_Home_dir} = "${swroot}/mods/GAR";
my ${VRT_ruleage} = "${swroot}/snort/VRT_ruleage";
my ${VRT_get_dir} = 'reg-rules';
my ${logfile} = "/var/log/snort/autoupdate-VRT.log";
#if (-e ${logfile}) { unlink ${logfile}; }
#open STDERR, ">>${logfile}";
open STDOUT, ">>${logfile}";

sub write_log {
  my (${message}) = @_;
  (${wkday},${month},${day},${time},${year}) = split(/\s+/, localtime);
  if (${day} < 10)
  {
    ${day} = " ${day}";
  }
  print "${month} ${day} ${time} ${message}";
}

sub get_the_time {
    (${second}, ${minute}, ${hour}, ${dayOfMonth}, ${month}, ${yearOffset}, ${dayOfWeek}, ${dayOfYear}, ${daylightSavings}) = localtime();
    ${year} = 1900 + ${yearOffset};
    ${theTime} = "${weekDays[${dayOfWeek}]} ${months[${month}]}";
    if (${dayOfMonth} < 10) {
	${theTime} = "${theTime} 0${dayOfMonth} ${year}";
    } else {
	${theTime} = "${theTime} ${dayOfMonth} ${year}";
    }
    if (${hour} < 10) {
	${theTime} = "${theTime} 0${hour}";
    } else {
	${theTime} = "${theTime} ${hour}";
    }
    if (${minute} < 10) {
	${theTime} = "${theTime}:0${minute}";
    } else {
	${theTime} = "${theTime}:${minute}";
    }
    if (${second} < 10) {
	${theTime} = "${theTime}:0${second}";
    } else {
	${theTime} = "${theTime}:${second}";
    }
}

sub get_newest {
    my ${dir} = shift;
    -d ${dir} or die "'${dir}' is not a directory...\n";
    my %files;
    File::Find::find (
	sub {
	    my ${name} = $File::Find::name;
	    # we want all *.rules files except emerging*.rules files
	    if (${name} =~ /.*\.rules/ &&
		${name} !~ /emerging.*\.rules/ &&
		${name} !~ /local\.rules/) {
		$files{${name}} = (stat ${name})[9] if -f ${name};
	    }
	}, ${dir}
    );
    ( sort { $files{$a} <=> $files{$b} } keys %files )[-1];
}

sub do_ruleage_closeout {
    my ${newest_file} = 'unknown';
    &write_log("Updating ${VRT_ruleage} file\n");
    &write_log("Collecting current update time:\n");
    &get_the_time;
    &write_log("  ${theTime}\n");
    &write_log("Storing update time\n");
    &write_log("  ${theTime}\n");
#    unlink "${VRT_ruleage}";
    open (FILE, ">${VRT_ruleage}");
    print FILE "${theTime}";
    close (FILE);
    &write_log("Locating newest VRT rules file:\n");
    ${newest_file} = get_newest("${swroot}/snort/rules");
    &write_log("  ${newest_file}\n");
    &write_log("Collecting ${newest_file}'s time stamps:\n");  
    (${a_stamp}, ${m_stamp}) = (stat ${newest_file})[8,9];
    &write_log("  ${a_stamp}  ${m_stamp}\n");
    &write_log("  " . scalar(localtime(${a_stamp})) . "\n");
    &write_log("  " . scalar(localtime(${m_stamp})) . "\n");
    &write_log("Storing time stamps to ${VRT_ruleage}\n");
    utime ${a_stamp}, ${m_stamp}, ${VRT_ruleage};
#    ${e_code} = $? >> 8;
#    ${s_code} = $? >> 127;
#    ${c_code} = $? >> 128;
#    printf( "DEBUG: %d: %s\n", ${e_code}, ${e_code} );
#    printf( "DEBUG: %d: %s\n", ${s_code}, ${s_code} );
#    printf( "DEBUG: %d: %s\n", ${c_code}, ${c_code} );
#    printf( "DEBUG: %d: %s\n", $!, $! );
    &write_log("Verifying ${VRT_ruleage}'s time stamps:\n");
    undef ${a_stamp}, ${m_stamp};
    (${a_stamp}, ${m_stamp}) = (stat ${VRT_ruleage})[8,9];
    &write_log("  ${a_stamp}  ${m_stamp}\n");
    &write_log("  " . scalar(localtime(${a_stamp})) . "\n");
    &write_log("  " . scalar(localtime(${m_stamp})) . "\n");
    &write_log("Setting ${VRT_ruleage} ownership to nobody:nobody\n");
    system("/bin/chown nobody:nobody ${VRT_ruleage}");
}

&write_log("-------------------------------------------------------------------------------\n");
&write_log("VRT SNORT Rules Auto-Updater - starting\n");

&write_log("Loading SNORT settings\n");
my %snortsettings;
&readhash("${swroot}/snort/settings", \%snortsettings);

if (${snortsettings{'OINK'}} !~ /^([\da-f]){40}$/i)
{
  &write_log("The Oink code must be 40 hex digits long\n");
  &write_log("Aborting...\n");
  goto EXIT;
}

my ${errormessage} = 'start';

if (${snortsettings{'ENABLE_SNORT'}} eq 'off') {
    &write_log("SNORT is not enabled.");
    &write_log("SNORT should be enabled for this rules update to be worth while.\n");
    &write_log("Continuing anyway...\n");
}

# start snort version query
open(MY_INPUT,"/usr/bin/snort -V 2>&1 |");
while(<MY_INPUT>) {
    chomp;
    if (/Version\s+(.*)/) {
       (${display_version}, ${sub1}, ${sub2}, ${sub3}) = split(/ /,$1);
       ${snort_version} = ${display_version};
       ${snort_version} =~ s/\.//g;
       ${display_version} .= " ${sub1} ${sub2} ${sub3}";
    }
}
close(MY_INPUT);
#${snort_version} = '2860';
while (length(${snort_version}) < 4) {
    ${snort_version} .= '0'; }
&write_log("Working with snort ${display_version} - [${snort_version}]\n");
#if (${snortsettings{'SUBSCRIBER'}} eq 'on') {
#    ${snort_version} = ${snort_version} . '_s';
#    ${VRT_get_dir} = 'sub-rules';
#    &write_log("We are a paying subscriber for the Sourcefire VRT rules sets\n");
#}
# end snort version query

my ${curdir} = getcwd;
my ${url} = 'http://www.snort.org/pub-bin/oinkmaster.cgi/' . ${snortsettings{'OINK'}} . "/snortrules-snapshot-${snort_version}.tar.gz";
# new oinkmaster url format for VRT??
#my ${url} = "http://www.snort.org/${VRT_get_dir}/snortrules-snapshot-${snort_version}.tar.gz/${snortsettings{'OINK'}}";
&write_log("Changing current directory to ${swroot}/snort/\n");
chdir "${swroot}/snort/";

my ${id} = 0;
while (${errormessage}) {
    ${id}++;
    &write_log("Executing oinkmaster\n");
    open(FD, "/usr/bin/oinkmaster.pl -C /usr/lib/smoothwall/oinkmaster.conf -o rules -u ${url} 2>&1 |");
    ${errormessage} = '';
    while(<FD>) {
	chomp;
	if (/ERROR 403:\s+(.*)/i) {
	    ${errormessage} = $1;
	}
	if (/ERROR 404:\s+(.*)/i) {
	    ${errormessage} = $1;
	}
	if (/ERROR 422:\s+(.*)/i) {
	    ${errormessage} = $1;
	}
	# uncomment the next line to log the output from oinkmaster
	&write_log("  oinkmaster: $_\n");
    }
    close(FD);
    if ($?) {
	&write_log("Attempt ${id}: $tr{'unable to fetch rules'}\n");
	&write_log("Reason: ${errormessage}\n");
	if ((${errormessage} eq "Not Found.") or (${errormessage} eq "Forbidden.")
	 or (${errormessage} eq "Unprocessable Entity.")) {
	    &write_log("Will not try again...\n");
	    last;
	} else {
	    if (${errormessage} and ${id} < 7) {
		&write_log("VRT 15 minute limit in effect. Will try again in 20 minutes...\n");
		sleep 1200;
	    }
	}
    } else {
	&do_ruleage_closeout;

	&write_log("Updating sid-msg.map\n");
	system("${GAR_Home_dir}/usr/bin/smoothwall/make-sidmap.pl");
	&write_log("Setting rules ownership to nobody:nobody\n");
	system("/bin/chown nobody:nobody ${swroot}/snort/rules/*");
	&write_log("Restarting snort\n");
	my ${success} = message('snortrestart');
	if (not defined ${success}) {
	    ${errormessage} = 'Unable to restart snort - see /var/log/messages for details'; }
	if (${errormessage}) {
	    &write_log("${errormessage}\n"); }
	${errormessage} = '';
    }
}

chdir ${curdir};

EXIT:

&write_log("VRT SNORT Rules Auto-Updater - complete\n");
