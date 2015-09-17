#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team
#
# Original code for guardian added by Drew S. DuPont (NetWhiz) for SmoothWall 2.0
#
# Code and updates for guardian for SWE 3.0 added by Stan Prescott and Mark Lewis

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );

use Cwd;
use Socket;

my (%SWEprodvals, %GAR_Settings, %CGI_Settings, %checked);
my ${GAR_Root_dir} = "/mods/GAR";
my ${GAR_Home_dir} = "${swroot}"."${GAR_Root_dir}";
my ${GAR_Logo} = "${GAR_Root_dir}/ui/img/alligator-gar-50-2.png";
my ${GAR_Settings_file} = "${GAR_Home_dir}/settings";
my ${GAR_Ignore_IP_details} = "${GAR_Home_dir}/config";
my ${GAR_Ignore_IP} = "${GAR_Home_dir}/etc/GAR.ignore";
my ${GAR_Conf_file} = "${GAR_Home_dir}/etc/GAR.conf";
my ${GAR_Script_file} = "$GAR_Home_dir/usr/bin/GAR";
&readhash("${swroot}/main/productdata",\%SWEprodvals);

my ${success};
my @max = (1 .. 4);
my @min = (1 .. 4);
my @loglvl = (1 .. 9);
my @timeqty = (0 .. 30);
my @timefmt = ('mins','hrs','days','wks','mons','no limit');

my @vars;
my ${var}, ${addr};
my ${needrestart} = 0;

&showhttpheaders();

# Get snort version
open(MY_INPUT,"/usr/bin/snort -V 2>&1 |");
while(<MY_INPUT>) {
    chomp;
    if (/Version\s+(.*)/) {
       (${SnortDisplayVersion}, ${sub1}, ${sub2}, ${sub3}, ${sub4}) = split(/ /,$1);
       ${SnortDLVersion} = "${SnortDisplayVersion}";
       ${SnortDLVersion} =~ s/\.//g;
       ${SnortDisplayVersion} = "${SnortDisplayVersion} ${sub1} ${sub2} ${sub3} ${sub4}";
    }
}
close(MY_INPUT);
 
# Get guardian version
open(MY_INPUT,"${GAR_Script_file} -v |");
my ${appID} = <MY_INPUT>;
close MY_INPUT;
chomp ${appID};

# Set some initial default values for guardian.conf
$GAR_Settings{'ENABLE_GUARD'} = 'off';
$GAR_Settings{'GUARD_STATE'} = 'off';
#$GAR_Settings{'ENABLE_GUARD'} = '';
#$GAR_Settings{'GUARD_STATE'} = '';
$GAR_Settings{'TIME_QTY'} = 2;
$GAR_Settings{'TIME_LIMIT'} = 'days';
$GAR_Settings{'PRI1_TIME_QTY'} = 7;
$GAR_Settings{'PRI1_TIME_LIMIT'} = 'days';
$GAR_Settings{'PRI2_TIME_QTY'} = 3;
$GAR_Settings{'PRI2_TIME_LIMIT'} = 'days';
$GAR_Settings{'PRI3_TIME_QTY'} = 1;
$GAR_Settings{'PRI3_TIME_LIMIT'} = 'days';
$GAR_Settings{'PRI4_TIME_QTY'} = 12;
$GAR_Settings{'PRI4_TIME_LIMIT'} = 'hrs';
$GAR_Settings{'MIN_PRIOR'} = 1;
$GAR_Settings{'MAX_PRIOR'} = 4;
$GAR_Settings{'MT_PRIOR'} = 'yes';
$GAR_Settings{'FORCE_LOG'} = 'no';
$GAR_Settings{'LOG_LVL'} = 4;
$GAR_Settings{'COLUMN'} = 1;
$GAR_Settings{'ORDER'} = $tr{'log ascending'};
#$GAR_Settings{'ACTION'} = '';
$GAR_Settings{'SIDS'} = '';
$GAR_Settings{'GIDS'} = '';

#print "<b>Initial Defaults:</b><br />\n";
#print "REQUEST METHOD:'" . $ENV{'REQUEST_METHOD'} . "'<br />\n";
#print "QUERY STRING:  '" . $ENV{'QUERY_STRING'} . "'<br />\n";
#print "CONTENT TYPE:  '" . $ENV{'CONTENT_TYPE'} . "'<br />\n";
#print "CONTENT LENGTH:'" . $ENV{'CONTENT_LENGTH'} . "'<br />\n";
#print "ACTION:        '" . $GAR_Settings{'ACTION'} . "'<br />\n";
#print "ENABLE_GUARD:  '" . $GAR_Settings{'ENABLE_GUARD'} . "'<br />\n";
#print "GUARD_STATE:   '" . $GAR_Settings{'GUARD_STATE'} . "'<br />\n";
#print "COLUMN:        '" . $GAR_Settings{'COLUMN'} . "'<br />\n";
#print "ORDER:         '" . $GAR_Settings{'ORDER'} . "'<br />\n";
#print "SIDS:          '" . $GAR_Settings{'SIDS'} . "'<br />\n";
#print "GIDS:          '" . $GAR_Settings{'GIDS'} . "'<br />\n";
#print "<br />\n";

# now read what is in settings file overwriting the above defaults
&readhash("${GAR_Settings_file}", \%GAR_Settings);
#print "<b>Settings File:</b><br />\n";
#print "REQUEST METHOD:'" . $ENV{'REQUEST_METHOD'} . "'<br />\n";
#print "QUERY STRING:  '" . $ENV{'QUERY_STRING'} . "'<br />\n";
#print "CONTENT TYPE:  '" . $ENV{'CONTENT_TYPE'} . "'<br />\n";
#print "CONTENT LENGTH:'" . $ENV{'CONTENT_LENGTH'} . "'<br />\n";
#print "ACTION:        '" . $GAR_Settings{'ACTION'} . "'<br />\n";
#print "ENABLE_GUARD:  '" . $GAR_Settings{'ENABLE_GUARD'} . "'<br />\n";
#print "GUARD_STATE:   '" . $GAR_Settings{'GUARD_STATE'} . "'<br />\n";
#print "COLUMN:        '" . $GAR_Settings{'COLUMN'} . "'<br />\n";
#print "ORDER:         '" . $GAR_Settings{'ORDER'} . "'<br />\n";
#print "SIDS:          '" . $GAR_Settings{'SIDS'} . "'<br />\n";
#print "GIDS:          '" . $GAR_Settings{'GIDS'} . "'<br />\n";
#print "<br />\n";

# now read what was submitted from the browser
#&GARgetcgihash(\%GAR_Settings);
#&GARgetcgihash(\%CGI_Settings);
&getcgihash(\%CGI_Settings);
if (not defined $CGI_Settings{'ENABLE_GUARD'}) {
    $CGI_Settings{'ENABLE_GUARD'} = 'off';
}
# now update the items in the GAR_Settings hash from the CGI_Settings hash
#if (defined $CGI_Settings{'ENABLE_GUARD'}) {
#    $GAR_Settings{'ENABLE_GUARD'}    = $CGI_Settings{'ENABLE_GUARD'}; }
if (defined $CGI_Settings{'GUARD_STATE'}) {
    $GAR_Settings{'GUARD_STATE'}     = $CGI_Settings{'GUARD_STATE'}; }
if (defined $CGI_Settings{'TIME_QTY'}) {
    $GAR_Settings{'TIME_QTY'}        = $CGI_Settings{'TIME_QTY'}; }
if (defined $CGI_Settings{'TIME_LIMIT'}) {
    $GAR_Settings{'TIME_LIMIT'}      = $CGI_Settings{'TIME_LIMIT'}; }
if (defined $CGI_Settings{'PRI1_TIME_QTY'}) {
    $GAR_Settings{'PRI1_TIME_QTY'}   = $CGI_Settings{'PRI1_TIME_QTY'}; }
if (defined $CGI_Settings{'PRI1_TIME_LIMIT'}) {
    $GAR_Settings{'PRI1_TIME_LIMIT'} = $CGI_Settings{'PRI1_TIME_LIMIT'}; }
if (defined $CGI_Settings{'PRI2_TIME_QTY'}) {
    $GAR_Settings{'PRI2_TIME_QTY'}   = $CGI_Settings{'PRI2_TIME_QTY'}; }
if (defined $CGI_Settings{'PRI2_TIME_LIMIT'}) {
    $GAR_Settings{'PRI2_TIME_LIMIT'} = $CGI_Settings{'PRI2_TIME_LIMIT'}; }
if (defined $CGI_Settings{'PRI3_TIME_QTY'}) {
    $GAR_Settings{'PRI3_TIME_QTY'}   = $CGI_Settings{'PRI3_TIME_QTY'}; }
if (defined $CGI_Settings{'PRI3_TIME_LIMIT'}) {
    $GAR_Settings{'PRI3_TIME_LIMIT'} = $CGI_Settings{'PRI3_TIME_LIMIT'}; }
if (defined $CGI_Settings{'PRI4_TIME_QTY'}) {
    $GAR_Settings{'PRI4_TIME_QTY'}   = $CGI_Settings{'PRI4_TIME_QTY'}; }
if (defined $CGI_Settings{'PRI4_TIME_LIMIT'}) {
    $GAR_Settings{'PRI4_TIME_LIMIT'} = $CGI_Settings{'PRI4_TIME_LIMIT'}; }
if (defined $CGI_Settings{'MIN_PRIOR'}) {
    $GAR_Settings{'MIN_PRIOR'}       = $CGI_Settings{'MIN_PRIOR'}; }
if (defined $CGI_Settings{'MAX_PRIOR'}) {
    $GAR_Settings{'MAX_PRIOR'}       = $CGI_Settings{'MAX_PRIOR'}; }
if (defined $CGI_Settings{'MT_PRIOR'}) {
    $GAR_Settings{'MT_PRIOR'}        = $CGI_Settings{'MT_PRIOR'}; }
if (defined $CGI_Settings{'FORCE_LOG'}) {
    $GAR_Settings{'FORCE_LOG'}       = $CGI_Settings{'FORCE_LOG'}; }
if (defined $CGI_Settings{'LOG_LVL'}) {
    $GAR_Settings{'LOG_LVL'}         = $CGI_Settings{'LOG_LVL'}; }
if (defined $CGI_Settings{'COLUMN'}) {
    $GAR_Settings{'COLUMN'}          = $CGI_Settings{'COLUMN'}; }
if (defined $CGI_Settings{'ORDER'}) {
    $GAR_Settings{'ORDER'}           = $CGI_Settings{'ORDER'}; }
if (defined $CGI_Settings{'SIDS'}) {
    $GAR_Settings{'SIDS'}            = $CGI_Settings{'SIDS'}; }
if (defined $CGI_Settings{'GIDS'}) {
    $GAR_Settings{'GIDS'}            = $CGI_Settings{'GIDS'}; }
if (defined $CGI_Settings{'ACTION'}) {
    $GAR_Settings{'ACTION'}          = $CGI_Settings{'ACTION'}; }
if (defined $CGI_Settings{'IP'}) {
    $GAR_Settings{'IP'}              = $CGI_Settings{'IP'}; }
if (defined $CGI_Settings{'COMMENT'}) {
    $GAR_Settings{'COMMENT'}         = $CGI_Settings{'COMMENT'}; }


my ${GAR_sids} = $GAR_Settings{'SIDS'};
my ${GAR_gids} = $GAR_Settings{'GIDS'};
chomp(${GAR_sids});
chomp(${GAR_gids});
${GAR_sids} =~ s/\n/,/g;
${GAR_gids} =~ s/\n/,/g;
$GAR_Settings{'SIDS'} = ${GAR_sids};
$GAR_Settings{'GIDS'} = ${GAR_gids};

if ($ENV{'QUERY_STRING'} && ( not defined $GAR_Settings{'ACTION'} or $GAR_Settings{'ACTION'} eq "" )) {
print "<b>Changing Sort Order!</b><br />\n";
    my @temp = split(',',$ENV{'QUERY_STRING'});
    $GAR_Settings{'COLUMN'} = $temp[0] if ( defined $temp[0] and $temp[0] ne "" );
    $GAR_Settings{'ORDER'}  = $temp[1] if ( defined $temp[1] and $temp[1] ne "" );
    # save the chosen sort column and order
    &writehash("${GAR_Settings_file}", \%GAR_Settings);
}

#print "<b>CGI Hash:</b><br />\n";
#print "REQUEST METHOD:'" . $ENV{'REQUEST_METHOD'} . "'<br />\n";
#print "QUERY STRING:  '" . $ENV{'QUERY_STRING'} . "'<br />\n";
#print "CONTENT TYPE:  '" . $ENV{'CONTENT_TYPE'} . "'<br />\n";
#print "CONTENT LENGTH:'" . $ENV{'CONTENT_LENGTH'} . "'<br />\n";
#print "ACTION:        '" . $GAR_Settings{'ACTION'} . "'<br />\n";
#print "ENABLE_GUARD1: '" . $CGI_Settings{'ENABLE_GUARD'} . "'<br />\n";
#print "ENABLE_GUARD2: '" . $GAR_Settings{'ENABLE_GUARD'} . "'<br />\n";
#print "GUARD_STATE:   '" . $GAR_Settings{'GUARD_STATE'} . "'<br />\n";
#print "COLUMN:        '" . $GAR_Settings{'COLUMN'} . "'<br />\n";
#print "ORDER:         '" . $GAR_Settings{'ORDER'} . "'<br />\n";
#print "SIDS:          '" . $GAR_Settings{'SIDS'} . "'<br />\n";
#print "GIDS:          '" . $GAR_Settings{'GIDS'} . "'<br />\n";
#print "<br />\n";

${errormessage} = '';

# Enable guardian
if ($GAR_Settings{'ACTION'} eq $tr{'save'} || $GAR_Settings{'ACTION'} eq $tr{'gar save config'}) {
#print "<b>Enable GAR:</b><br />\n";
#    if (($GAR_Settings{'ENABLE_GUARD'} eq 'on') &&
    if (($CGI_Settings{'ENABLE_GUARD'} eq 'on') &&
    ($GAR_Settings{'GUARD_STATE'} eq 'off')) {
#print "<b>on:off</b><br />\n";
        # turn on and start GAR. GUARD_STATE indicates current run state.
	&log($tr{'gar is being enabled'});
	$GAR_Settings{'ENABLE_GUARD'} = 'on';
	$GAR_Settings{'GUARD_STATE'} = 'on';
	&log($tr{'gar is being started'});
	&writehash("${GAR_Settings_file}", \%GAR_Settings);
	${success} = message('guardianstart');
	if (not defined ${success}) {
	    ${errormessage} = $tr{'smoothd failure'}; 
	}
#    } elsif (($GAR_Settings{'ENABLE_GUARD'} eq 'off') &&
    } elsif (($CGI_Settings{'ENABLE_GUARD'} eq 'off') &&
    ($GAR_Settings{'GUARD_STATE'} eq 'on')) {
#print "<b>off:on</b><br />\n";
        # turn off and stop GAR. GUARD_STATE indicates current run state.
	&log($tr{'gar is being disabled'});
	$GAR_Settings{'ENABLE_GUARD'} = 'off';
	$GAR_Settings{'GUARD_STATE'} = 'off';
	&log($tr{'gar is being terminated'});
	&writehash("${GAR_Settings_file}", \%GAR_Settings);
	${success} = message('guardianstop');
	if (not defined ${success}) {
	    ${errormessage} = $tr{'smoothd failure'}; 
	}
    }
}

if ( defined $GAR_Settings{'ACTION'} and $GAR_Settings{'ACTION'} eq $tr{'gar save config'} ) {
    # Convert time limit settings to secs to write to guardian.conf
    my (${timelimit0}, ${timelimit1}, ${timelimit2}, ${timelimit3}, ${timelimit4});
    my ${min_secs} = 60;
    my ${hour_secs} = 60*${min_secs};
    my ${day_secs} = 24*${hour_secs};
    my ${week_secs} = 7*${day_secs};
    my ${month_secs} = 30*${day_secs};
    @myTimeLimits = ('TIME_LIMIT','PRI1_TIME_LIMIT','PRI2_TIME_LIMIT','PRI3_TIME_LIMIT','PRI4_TIME_LIMIT');
    foreach ${tlimit} (@myTimeLimits) {
	if ($GAR_Settings{${tlimit}} eq "mins") {
	    if (${tlimit} eq 'TIME_LIMIT') {
		${timelimit0} = $GAR_Settings{'TIME_QTY'}*${min_secs};
	    } elsif (${tlimit} eq 'PRI1_TIME_LIMIT') {
		${timelimit1} = $GAR_Settings{'PRI1_TIME_QTY'}*${min_secs};
	    } elsif (${tlimit} eq 'PRI2_TIME_LIMIT') {
		${timelimit2} = $GAR_Settings{'PRI2_TIME_QTY'}*${min_secs};
	    } elsif (${tlimit} eq 'PRI3_TIME_LIMIT') {
		${timelimit3} = $GAR_Settings{'PRI3_TIME_QTY'}*${min_secs};
	    } elsif (${tlimit} eq 'PRI4_TIME_LIMIT') {
		${timelimit4} = $GAR_Settings{'PRI4_TIME_QTY'}*${min_secs};
	    }
	} elsif ($GAR_Settings{${tlimit}} eq "hrs") {
	    if (${tlimit} eq 'TIME_LIMIT') {
		${timelimit0} = $GAR_Settings{'TIME_QTY'}*${hour_secs};
	    } elsif (${tlimit} eq 'PRI1_TIME_LIMIT') {
		${timelimit1} = $GAR_Settings{'PRI1_TIME_QTY'}*${hour_secs};
	    } elsif (${tlimit} eq 'PRI2_TIME_LIMIT') {
		${timelimit2} = $GAR_Settings{'PRI2_TIME_QTY'}*${hour_secs};
	    } elsif (${tlimit} eq 'PRI3_TIME_LIMIT') {
		${timelimit3} = $GAR_Settings{'PRI3_TIME_QTY'}*${hour_secs};
	    } elsif (${tlimit} eq 'PRI4_TIME_LIMIT') {
		${timelimit4} = $GAR_Settings{'PRI4_TIME_QTY'}*${hour_secs};
	    }
	} elsif ($GAR_Settings{${tlimit}} eq "days") {
	    if (${tlimit} eq 'TIME_LIMIT') {
		${timelimit0} = $GAR_Settings{'TIME_QTY'}*${day_secs};
	    } elsif (${tlimit} eq 'PRI1_TIME_LIMIT') {
		${timelimit1} = $GAR_Settings{'PRI1_TIME_QTY'}*${day_secs};
	    } elsif (${tlimit} eq 'PRI2_TIME_LIMIT') {
		${timelimit2} = $GAR_Settings{'PRI2_TIME_QTY'}*${day_secs};
	    } elsif (${tlimit} eq 'PRI3_TIME_LIMIT') {
		${timelimit3} = $GAR_Settings{'PRI3_TIME_QTY'}*${day_secs};
	    } elsif (${tlimit} eq 'PRI4_TIME_LIMIT') {
		${timelimit4} = $GAR_Settings{'PRI4_TIME_QTY'}*${day_secs};
	    }
	} elsif ($GAR_Settings{${tlimit}} eq "wks") {
	    if (${tlimit} eq 'TIME_LIMIT') {
		${timelimit0} = $GAR_Settings{'TIME_QTY'}*${week_secs};
	    } elsif (${tlimit} eq 'PRI1_TIME_LIMIT') {
		${timelimit1} = $GAR_Settings{'PRI1_TIME_QTY'}*${week_secs};
	    } elsif (${tlimit} eq 'PRI2_TIME_LIMIT') {
		${timelimit2} = $GAR_Settings{'PRI2_TIME_QTY'}*${week_secs};
	    } elsif (${tlimit} eq 'PRI3_TIME_LIMIT') {
		${timelimit3} = $GAR_Settings{'PRI3_TIME_QTY'}*${week_secs};
	    } elsif (${tlimit} eq 'PRI4_TIME_LIMIT') {
		${timelimit4} = $GAR_Settings{'PRI4_TIME_QTY'}*${week_secs};
	    }
	} elsif ($GAR_Settings{${tlimit}} eq "mons") {
	    if (${tlimit} eq 'TIME_LIMIT') {
		${timelimit0} = $GAR_Settings{'TIME_QTY'}*${month_secs};
	    } elsif (${tlimit} eq 'PRI1_TIME_LIMIT') {
		${timelimit1} = $GAR_Settings{'PRI1_TIME_QTY'}*${month_secs};
	    } elsif (${tlimit} eq 'PRI2_TIME_LIMIT') {
		${timelimit2} = $GAR_Settings{'PRI2_TIME_QTY'}*${month_secs};
	    } elsif (${tlimit} eq 'PRI3_TIME_LIMIT') {
		${timelimit3} = $GAR_Settings{'PRI3_TIME_QTY'}*${month_secs};
	    } elsif (${tlimit} eq 'PRI4_TIME_LIMIT') {
		${timelimit4} = $GAR_Settings{'PRI4_TIME_QTY'}*${month_secs};
	    }
	} elsif ($GAR_Settings{${tlimit}} eq "no limit") {
	    if (${tlimit} eq 'TIME_LIMIT') {
		${timelimit0} = 99999999;
	    } elsif (${tlimit} eq 'PRI1_TIME_LIMIT') {
		${timelimit1} = 99999999;
	    } elsif (${tlimit} eq 'PRI2_TIME_LIMIT') {
		${timelimit2} = 99999999;
	    } elsif (${tlimit} eq 'PRI3_TIME_LIMIT') {
		${timelimit3} = 99999999;
	    } elsif (${tlimit} eq 'PRI4_TIME_LIMIT') {
		${timelimit4} = 99999999;
	    }
	}
    }
    open(FILE, "${GAR_Conf_file}") or die "Unable to open ${GAR_Conf_file} for input.";
    my @temp = <FILE>;
    close FILE;
    my ${line};
    my @split;
    open(FILE, ">${GAR_Conf_file}") or die "Unable to open ${GAR_Conf_file} for output.";
    foreach ${line} (@temp) {
	chomp ${line};
	@split = split(/\t+/, ${line});
	if ($split[0] eq "TimeLimit") {
	    print FILE "TimeLimit\t${timelimit0}\n";
	} elsif ($split[0] eq "Pri1TimeLimit") {
	    print FILE "Pri1TimeLimit\t${timelimit1}\n";
	} elsif ($split[0] eq "Pri2TimeLimit") {
	    print FILE "Pri2TimeLimit\t${timelimit2}\n";
	} elsif ($split[0] eq "Pri3TimeLimit") {
	    print FILE "Pri3TimeLimit\t${timelimit3}\n";
	} elsif ($split[0] eq "Pri4TimeLimit") {
	    print FILE "Pri4TimeLimit\t${timelimit4}\n";
	} elsif ($split[0] eq "MinPriority") {
	    print FILE "MinPriority\t$GAR_Settings{'MIN_PRIOR'}\n";
	} elsif ($split[0] eq "MaxPriority") {
	    print FILE "MaxPriority\t$GAR_Settings{'MAX_PRIOR'}\n";
	} elsif ($split[0] eq "MTPriority") {
	    print FILE "MTPriority\t$GAR_Settings{'MT_PRIOR'}\n";
	} elsif ($split[0] eq "ForceLogging") {
	    print FILE "ForceLogging\t$GAR_Settings{'FORCE_LOG'}\n";
	} elsif ($split[0] eq "LogMsgLevel") {
	    print FILE "LogMsgLevel\t$GAR_Settings{'LOG_LVL'}\n";
	} elsif ($split[0] eq "IgnoreSIDs") {
	    print FILE "IgnoreSIDs\t$GAR_Settings{'SIDS'}\n";
	} elsif ($split[0] eq "IgnoreGIDs") {
	    print FILE "IgnoreGIDs\t$GAR_Settings{'GIDS'}\n";
	} else {
	    print FILE "${line}\n";
	}
    }
    close FILE;
    &writehash("${GAR_Settings_file}", \%GAR_Settings);
}

if (-s "${GAR_Ignore_IP}" and -z "${GAR_Ignore_IP_details}") {
    open (IGNORE, "${GAR_Ignore_IP}") or die "Unable to open ${GAR_Ignore_IP} file for input.";
    @temp = <IGNORE>;
    close IGNORE;
    open (FILE, ">${GAR_Ignore_IP_details}") or die "Unable to open ${GAR_Ignore_IP_details} file for output.";
    flock FILE, 2;
    foreach $line (@temp) {
	chomp ${line};
	my ${srcname} = gethostbyaddr(inet_aton(${line}), AF_INET);
	if (${srcname} eq '') {
	    ${srcname} = ${line};
	}
	print FILE "${line},${srcname},,on\n";
    }
    close FILE;
}

if ( defined $GAR_Settings{'ACTION'} and $GAR_Settings{'ACTION'} eq $tr{'add'} ) {
    my ${ip} = $GAR_Settings{'IP'};
    my ${comment} = $GAR_Settings{'COMMENT'};
	
    unless(&validipormask(${ip})) { ${errormessage} = $tr{'source ip bad'}; }
    my ${srcname} = gethostbyaddr(inet_aton(${ip}), AF_INET);
    if (${srcname} eq '') {
	${srcname} = ${ip};
    }

    unless (${errormessage}) {
	open (FILE,">>${GAR_Ignore_IP_details}") or die 'Unable to open config file for output.';
	flock FILE, 2;
	print FILE "${ip},${srcname},${comment},on\n";
	close (FILE);

	open (TEMP, ">>${GAR_Ignore_IP}") or die 'Unable to open ignore file for output.';
	flock TEMP, 2;
	print TEMP "${ip}\n";
	close TEMP;
    }
    $GAR_Settings{'IP'} = '';
    $GAR_Settings{'COMMENT'} = '';
#    &writehash("${GAR_Settings_file}", \%GAR_Settings);
}

if ( defined $GAR_Settings{'ACTION'} and $GAR_Settings{'ACTION'} eq $tr{'remove'} 
or $GAR_Settings{'ACTION'} eq $tr{'edit'}) {
    open(FILE, "${GAR_Ignore_IP_details}") or die 'Unable to open ignore config file for input.';
    my @current = <FILE>;
    close(FILE);
    my ${id} = 0;
    foreach ${line} (@current) {
	${id}++;
#	if ($GAR_Settings{${id}} eq "on") {
	if ($CGI_Settings{${id}} eq "on") {
	    ${count}++; 
	}
    }

    if (${count} == 0) {
	${errormessage} = $tr{'nothing selected'};
    }
    if (${count} > 1 && $GAR_Settings{'ACTION'} eq $tr{'edit'}) {
	${errormessage} = $tr{'you can only select one item to edit'}; 
    }
	
    unless (${errormessage}) {
	open(FILE, ">${GAR_Ignore_IP_details}") or die 'Unable to open config file for output.';
	flock FILE, 2;
	${id} = 0;
	foreach ${line} (@current) {
	    ${id}++;
#	    unless ($GAR_Settings{${id}} eq "on") {
	    unless ($CGI_Settings{${id}} eq "on") {
		print FILE "${line}"; 
	    } elsif ($GAR_Settings{'ACTION'} eq $tr{'edit'}) {
		chomp ${line};
		my @temp2 = split(/\,/, ${line});
		$GAR_Settings{'IP'} = $temp2[0];
		$GAR_Settings{'COMMENT'} = $temp2[2];
	    }
	}
	close(FILE);

	open(FILE, ${GAR_Ignore_IP_details}) or die 'Unable to open config file for input.';
	@current = <FILE>;
	close FILE;

	open(FILE, ">${GAR_Ignore_IP}") or die 'Unable to open ignore file for output.';
	foreach ${line} (@current) {
	    @split = split(/\,/, ${line});
	    print FILE "$split[0]\n";
	}
	close FILE;
    }
#    &writehash("${GAR_Settings_file}", \%GAR_Settings);
}

my @temp;
my @split;
my ${line};
my ${splitline};

$checked{'ENABLE_GUARD'}{'off'} = '';
$checked{'ENABLE_GUARD'}{'on'} = '';
$checked{'ENABLE_GUARD'}{$GAR_Settings{'ENABLE_GUARD'}} = 'CHECKED';
$selected{'MIN_PRIOR'}{$GAR_Settings{'MIN_PRIOR'}} = 'SELECTED';
$selected{'MAX_PRIOR'}{$GAR_Settings{'MAX_PRIOR'}} = 'SELECTED';
$selected{'MT_PRIOR'}{$GAR_Settings{'MT_PRIOR'}} = 'SELECTED';
$selected{'FORCE_LOG'}{$GAR_Settings{'FORCE_LOG'}} = 'SELECTED';
$selected{'TIME_LIMIT'}{$GAR_Settings{'TIME_LIMIT'}} = 'SELECTED';
$selected{'PRI1_TIME_LIMIT'}{$GAR_Settings{'PRI1_TIME_LIMIT'}} = 'SELECTED';
$selected{'PRI2_TIME_LIMIT'}{$GAR_Settings{'PRI2_TIME_LIMIT'}} = 'SELECTED';
$selected{'PRI3_TIME_LIMIT'}{$GAR_Settings{'PRI3_TIME_LIMIT'}} = 'SELECTED';
$selected{'PRI4_TIME_LIMIT'}{$GAR_Settings{'PRI4_TIME_LIMIT'}} = 'SELECTED';
$selected{'TIME_QTY'}{$GAR_Settings{'TIME_QTY'}} = 'SELECTED';
$selected{'PRI1_TIME_QTY'}{$GAR_Settings{'PRI1_TIME_QTY'}} = 'SELECTED';
$selected{'PRI2_TIME_QTY'}{$GAR_Settings{'PRI2_TIME_QTY'}} = 'SELECTED';
$selected{'PRI3_TIME_QTY'}{$GAR_Settings{'PRI3_TIME_QTY'}} = 'SELECTED';
$selected{'PRI4_TIME_QTY'}{$GAR_Settings{'PRI4_TIME_QTY'}} = 'SELECTED';
$selected{'LOG_LVL'}{$GAR_Settings{'LOG_LVL'}} = 'SELECTED';

&openpage($tr{'gar'}, 1, '', 'services');

&openbigbox('100%', 'LEFT');

print "<FORM METHOD='POST'>\n";

&alertbox(${errormessage});

&openbox($tr{'gar2'});

print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD WIDTH='25%' style='text-align: left; padding: 4pt .5em 4pt 1em;'>$tr{'enabled'}&nbsp;&nbsp;<INPUT TYPE='checkbox' NAME='ENABLE_GUARD' $checked{'ENABLE_GUARD'}{'on'}><INPUT TYPE='hidden' NAME='GUARD_STATE' VALUE='$GAR_Settings{'GUARD_STATE'}'></TD>
	<TD WIDTH='25%' style='text-align: center; padding: 4pt .5em 4pt 1em;'>${appID}</TD>
	<TD WIDTH='25%' style='text-align: right; padding: 4pt .5em 4pt 1em;'><A style='color: blue;'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'save'}'></TD>
    </TR>
    <TR>
	<TD WIDTH='25%' style='text-align: left; padding: 4pt .5em 4pt 1em;'><A style='color: blue;' HREF='/mods/GAR/snortstats/garstats.cgi'>$tr{'garsnortstats link'}</A></TD>
	<TD WIDTH='25%' style='text-align: center; padding: 4pt .5em 4pt 1em;'>Snort ${SnortDisplayVersion}</TD>
	<TD WIDTH='25%' style='text-align: right; padding: 4pt .5em 4pt 1em;'><A style='color: blue;' HREF='gartool.cgi'>$tr{'gartool link'}</A></TD>
    </TR>
</TABLE>
END
;

&closebox();

&openbox($tr{'gar limits and settings'});

print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD COLSPAN='6' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD COLSPAN='3' ALIGN='CENTER'><B>$tr{'gar blocking time limits'}</B></TD>
	<TD COLSPAN='3' ALIGN='CENTER'><B>$tr{'gar priorities and logging'}</B></TD>
    </TR>
    <TR>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    &nbsp;&nbsp;$tr{'gar block default'} 
	    <SELECT TYPE='MENU' NAME='TIME_QTY'>
END
;
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='TIME_LIMIT'>
END
;
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    $tr{'gar min pri'} 
	    <SELECT TYPE='MENU' NAME='MIN_PRIOR'>
END
;
	foreach (@min) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'MIN_PRIOR'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    $tr{'gar block pri1'} 
	    <SELECT TYPE='MENU' NAME='PRI1_TIME_QTY'>
END
;
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI1_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI1_TIME_LIMIT'>
END
;
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI1_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    $tr{'gar max pri'} 
	    <SELECT TYPE='MENU' NAME='MAX_PRIOR'>
END
;
	foreach (@max) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'MAX_PRIOR'}{$_}>$_</OPTION>\n";
	}
	print <<END;
 	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    $tr{'gar block pri2'} 
	    <SELECT TYPE='MENU' NAME='PRI2_TIME_QTY'>
END
;
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI2_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI2_TIME_LIMIT'>
END
;
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI2_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    $tr{'gar empty pri'} 
	    <SELECT TYPE='MENU' NAME='MT_PRIOR'>
		<OPTION VALUE='yes' $selected{'MT_PRIOR'}{yes}>yes</OPTION>
		<OPTION VALUE='no' $selected{'MT_PRIOR'}{no}>no</OPTION>
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    $tr{'gar block pri3'} 
	    <SELECT TYPE='MENU' NAME='PRI3_TIME_QTY'>
END
;
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI3_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI3_TIME_LIMIT'>
END
;
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI3_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    $tr{'gar log hits'} 
	    <SELECT TYPE='MENU' NAME='FORCE_LOG'>
		<OPTION VALUE='yes' $selected{'FORCE_LOG'}{yes}>yes</OPTION>
		<OPTION VALUE='no' $selected{'FORCE_LOG'}{no}>no</OPTION>
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    $tr{'gar block pri4'} 
	    <SELECT TYPE='MENU' NAME='PRI4_TIME_QTY'>
END
;
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI4_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI4_TIME_LIMIT'>
END
;
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI4_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    $tr{'gar log level'} 
	    <SELECT TYPE='MENU' NAME='LOG_LVL'>
END
;
	foreach (@loglvl) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'LOG_LVL'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='10%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD COLSPAN='6' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
</TABLE>
END
;

&closebox();

&openbox($tr{'gar snort and generator ids'});

print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD COLSPAN='3' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar gid whitelist'}</B></TD>
	<TD WIDTH='10%' ALIGN='CENTER'>&nbsp;</TD>
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar sid whitelist'}</B></TD>
    </TR>
    <TR>
	<TD ALIGN='CENTER' VALIGN='TOP'>
	    <TEXTAREA NAME='GIDS' COLS='25' ROWS='10'>
END
;
    my @mysplit;
    @mysplit = split(/\,/, $GAR_Settings{'GIDS'});
    foreach $gid (@mysplit) {
	chomp $gid;
	$gid =~ s/^\s+//;
	$gid =~ s/\s+$//;
	if (length($gid) > 0) {
	    print "$gid\n";
	}
    }

print <<END;
</TEXTAREA>
	</TD>
	<TD WIDTH='10%' ALIGN='CENTER'>&nbsp;</TD>
	<TD ALIGN='CENTER' VALIGN='TOP'>
	    <TEXTAREA NAME='SIDS' COLS='25' ROWS='10'>
END
;
    @mysplit = split(/\,/, $GAR_Settings{'SIDS'});
    foreach $sid (@mysplit) {
	chomp $sid;
	$sid =~ s/^\s+//;
	$sid =~ s/\s+$//;
	if (length($sid) > 0) {
	    print "$sid\n";
	}
    }

print <<END;
</TEXTAREA>
	</TD>
    </TR>
    <TR>
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar gid rules'}</B></TD>
	<TD WIDTH='10%' ALIGN='CENTER'>&nbsp;</TD>
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar sid rules'}</B></TD>
    </TR>
</TABLE>
<BR>
<TABLE WIDTH='100%'>
    <TR>
	<TD ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'gar save config'}'></TD>
    </TR>
</TABLE>
<BR>
END
;

&closebox();

&openbox($tr{'gar ip whitelist'});

print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD COLSPAN='4' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD ALIGN='CENTER'>$tr{'gar ip'}</TD>
	<TD ALIGN='LEFT'><INPUT TYPE='text' NAME='IP' VALUE='$GAR_Settings{'IP'}' SIZE='25'></TD>
	<TD ALIGN='CENTER'>$tr{'gar comment'}</TD>
	<TD ALIGN='LEFT'><INPUT TYPE='text' NAME='COMMENT' VALUE='$GAR_Settings{'COMMENT'}' SIZE='40'></TD>
    </TR>
    <TR>
	<TD COLSPAN='4' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD COLSPAN='4' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'add'}'></TD>
    </TR>
    <TR>
	<TD COLSPAN='4' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
</TABLE>
END
;

my %render_settings = 
(
#	'url'     => "$tr{'ssgar'}.cgi?[%COL%],[%ORD%],$GAR_Settings{'COLUMN_TWO'},$GAR_Settings{'ORDER_TWO'}",
	'url'     => "$tr{'ssgar'}.cgi?[%COL%],[%ORD%]",
	'columns' => [ 
		{ 
			column => '1',
			title  => "$tr{'gar ip2'}",
			size   => 30,
			sort   => \&ipcompare,
		},
		{
			column => '2',
			title  => "$tr{'gar hostname'}",
			size   => 30,
			sort	=> 'cmp',
		},
		{ 
			column => '3',
			title => "$tr{'comment'}",
			size   => 30,
			sort	=> 'cmp',
		},
		{
			title  => "$tr{'mark'}", 
			size   => 5,
			mark   => ' ',
		}
	]
);

print <<END;
<script type=\"text/javascript\">
<!--
function displayGAR_Tracker(url) {
    if ("$SWEprodvals{'VERSION'}" == "3.0") {
        window.open("/cgi-bin/mods/GAR/gartracker.cgi?track="+url,"disposableHelpWindow","resizable=yes,status=no,scrollbars=yes,width=650,height=500");
    } else {
        window.open("/mods/GAR/cgi-bin/gartracker.cgi?track="+url,"disposableHelpWindow","resizable=yes,status=no,scrollbars=yes,width=650,height=500");
    }
}
//-->
</script>

<script type=\"text/javascript\">
<!--
function GARviewPort() {
    var h = window.innerHeight || document.documentElement.clientHeight || document.getElementsByTagName('body')[0].clientHeight;
    var w = window.innerWidth || document.documentElement.clientWidth || document.getElementsByTagName('body')[0].clientWidth;
    return { width : w , height : h }
}
//-->
</script>

<script type=\"text/javascript\">
<!--
var page_height;
var whitelist_height;

page_height = GARviewPort().height;
whitelist_height = parseInt(page_height - 378);
if (page_height >= 525) {
    document.write("<div style='height: " + whitelist_height + "px; width: 100%; overflow: auto;'>");
} else {
    document.write("<div>");
}
//-->
</script>
END
;

&displaytable( ${GAR_Ignore_IP_details}, \%render_settings, $GAR_Settings{'ORDER'}, $GAR_Settings{'COLUMN'} );

print <<END;
<script type=\"text/javascript\">
<!--
document.write("</div><br/>");
//-->
</script>
END
;

print <<END
<TABLE WIDTH='100%'>
<TR>
    <TD WIDTH='33%' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'remove'}'></TD>
    <TD WIDTH='33%' ALIGN='CENTER'><script type=\"text/javascript\">document.write("PGH:" + page_height + " WLH:" + whitelist_height + "<br/>");</script></TD>
    <TD WIDTH='34%' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'edit'}'></TD>
</TR>
</TABLE>
END
;

&closebox();

&alertbox('add','add');

print "</FORM>\n";

&closebigbox();

print <<END;
<script type=\"text/javascript\">
<!--
var mainbody = document.getElementsByClassName('mainbody');
mainbody[0].style.backgroundImage = "url('${GAR_Logo}')";
mainbody[0].style.backgroundSize = "contain";
//-->
</script>
END
;

# close except </body> and </html>
&closepage( "update" );

print <<END;
</body>
</html>
END
;

sub GARgetcgihash {
    my $hash = $_[0];
    my $buffer = '';
    my $length = $ENV{'CONTENT_LENGTH'};
    my ($name, $value);
    my ($pair, @pairs, $read);
    my %hash;
    my $boundary;
    my %remotesettings;
    my %main;
    my %netsettings;
    my $redip = '0.0.0.0';
    my $referer;
    my $shorthostname;
    my @hostnameelements;

    if ($ENV{'REQUEST_METHOD'} ne 'POST') {
        return; }

    $ENV{'HTTP_REFERER'} =~ m/^(http|https)\:\/\/(.*?)[\:|\/]/;
    $referer = $2;

    &readhash("${swroot}/remote/settings", \%remotesettings);
    &readhash("${swroot}/main/settings", \%main);
    &readhash("${swroot}/ethernet/settings", \%netsettings);

    @hostnameelements = split(/\./, $main{'HOSTNAME'});
    $shorthostname = $hostnameelements[0];

    if (open(FILE, "${swroot}/red/local-ipaddress")) {
        $redip = <FILE>; chomp $redip;
        close(FILE);
    }

    if ($remotesettings{'ENABLE_SECURE_ADMIN'} eq 'on') {
	unless ($referer eq $main{'HOSTNAME'} ||
		$referer eq $shorthostname ||
		$referer eq $netsettings{'GREEN_ADDRESS'} ||
		$referer eq $redip)
	{
	    &log("Referral $ENV{'HTTP_REFERER'} is not a SmoothWall page.");
	    return;
	}
    }

    $read = 0;
    $buffer = "";
#    while($read < $length) {
#	$read = $read + (read(STDIN, $buf, 1024) or die "Could not read buffer:$read: $@");
#        $buffer .= $buf;
#    }
#    unless($read == $length) {
#        die "Could not read buffer: $!";
#    }
    read(STDIN, $buffer, $length);
    
    if($ENV{'CONTENT_TYPE'} =~ m/multipart\/form-data; boundary=(.*)/) {
        $boundary = $1;
        chomp $boundary;
        $boundary =~ s/\+/ /g;
        foreach (split(/$boundary/,$buffer)) {
            s!--$!!so;
            if(m/Content-Disposition: form-data; name="(.*?)"/is) {
                $name = $1;
            }
            if(m/Content-Disposition: form-data; name="$name".*?\015\012\015\012(.*)$/is) {
                $value = $1;
                $value =~ s!\015\012$!!so;
                $hash->{$name} = $value;
            } else { next; }
        }
    } else {
        @pairs = split(/&/, $buffer);

        foreach $pair (@pairs) {
            $pair =~ s/\+/ /g;
print "CGI pair: '" . $pair . "'<br />\n";	    
            ($name, $value) = split(/=/, $pair);
print "CGI pair: &nbsp;" . $name . "=" . $value . "<br />\n";	    
            next unless $name; # fields MUST BE named!
            $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack('C', hex($1))/eg;
            $value =~s/[^\w\013\n!@#\$%\^\*()_\-\+=\{\}\[\]\\|;:\'\"<,>\.?\/`~\& ]//g;
            $hash->{$name} = $value;
	}
    }
    return %hash;
}
