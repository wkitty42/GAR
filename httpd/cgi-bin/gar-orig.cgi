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

my (%GAR_settings, %checked);
my $GAR_Home_dir = "${swroot}/mods/GAR";
my $GAR_Settings_file = "${GAR_Home_dir}/settings";
my $GAR_Ignore_IP_details = "${GAR_Home_dir}/config";
my $GAR_Ignore_IP = "/etc/guardian.ignore";
my $GAR_Conf_file = "/etc/guardian.conf";

my $success;
my @max = (1 .. 4);
my @min = (1 .. 4);
my @loglvl = (1 .. 9);
my @timeqty = (0 .. 30);
my @timefmt = ('mins','hrs','days','wks','mons','no limit');

my @vars;
my $var, $addr;
my $needrestart = 0;

&showhttpheaders();

# Get snort version
open(MY_INPUT,"snort -V 2>&1 |");
while(<MY_INPUT>) {
    chomp;
    if (/Version\s+(.*)/i) {
       ($snortDisplayversion, $sub1, $sub2) = split(/ /,$1);
       $snortDLversion = "$snortDisplayversion";
       $snortDLversion =~ s/\.//g;
       $snortDisplayversion = "$snortDisplayversion $sub1 $sub2";
    }
}
close(MY_INPUT);
 
# Get guardian version
open(FILE,"/usr/local/sbin/guardian.pl -v |");
my $guardver = <FILE>;
close FILE;
chomp $guardver;
my @guardver = split(/\s/, $guardver);
my $guard_ver = $guardver[1];

# Set some initial default values for guardian.conf
$GAR_Settings{'ENABLE_GUARD'} = 'off';
$GAR_Settings{'GUARD_STATE'} = 'off';
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
$GAR_Settings{'ACTION'} = '';
# now read what is in settings file overwriting the above defaults
&readhash("$GAR_Settings_file", \%GAR_Settings);
# now read what was submitted from the browser overwriting the above
&getcgihash(\%GAR_Settings);

if ($ENV{'QUERY_STRING'} && ( not defined $GAR_Settings{'ACTION'} or $GAR_Settings{'ACTION'} eq "" )) {
    my @temp = split(',',$ENV{'QUERY_STRING'});
    $GAR_Settings{'COLUMN'} = $temp[0] if ( defined $temp[ 0 ] and $temp[ 0 ] ne "" );
    $GAR_Settings{'ORDER'}  = $temp[1] if ( defined $temp[ 1 ] and $temp[ 1 ] ne "" );
    # save the chosen sort column and order
    &writehash("$GAR_Settings_file", \%GAR_Settings);
}

$errormessage = '';

if (-s "$GAR_Ignore_IP" and -z "$GAR_Ignore_IP_details") {
    open (IGNORE, "$GAR_Ignore_IP") or die "Unable to open $GAR_Ignore_IP file for input.";
    @temp = <IGNORE>;
    close IGNORE;
    open (FILE, ">$GAR_Ignore_IP_details") or die "Unable to open $GAR_Ignore_IP_details file for output.";
    flock FILE, 2;
    foreach $line (@temp) {
	chomp $line;
	my $srcname = gethostbyaddr(inet_aton($line), AF_INET);
	if ($srcname eq '') {
	    $srcname = $line;
	}
	print FILE "$line,$srcname,,on\n";
    }
    close FILE;
}

# Enable guardian
if ($GAR_Settings{'ACTION'} eq $tr{'save'}) {
    if ($GAR_Settings{'ENABLE_GUARD'} eq 'on') {
	if ($GAR_Settings{'GUARD_STATE'} eq 'off') {
    	    &log($tr{'guardian is enabled'});
	    $GAR_Settings{'GUARD_STATE'} = 'on';
	    &writehash("$GAR_Settings_file", \%GAR_Settings);
 	    $success = message('guardianrestart');
 	    if (not defined $success) {
   		$errormessage = $tr{'smoothd failure'}; 
	    }
	}
    } elsif ($GAR_Settings{'ENABLE_GUARD'} eq 'off') {
	if ($GAR_Settings{'GUARD_STATE'} eq 'on') {
	    &log($tr{'guardian is disabled'});
	    $GAR_Settings{'GUARD_STATE'} = 'off';
	    &writehash("$GAR_Settings_file", \%GAR_Settings);
	    $success = message('guardianrestart');
	    if (not defined $success) {
		$errormessage = $tr{'smoothd failure'};
	    }
	}
    }
}

if ( defined $GAR_Settings{'ACTION'} and $GAR_Settings{'ACTION'} eq $tr{'gar save config'} ) {
    # Convert time limit settings to secs to write to guardian.conf
    my ($timelimit, $timelimit1, $timelimit2, $timelimit3, $timelimit4);
    my $min_secs = 60;
    my $hour_secs = 60*$min_secs;
    my $day_secs = 24*$hour_secs;
    my $week_secs = 7*$day_secs;
    my $month_secs = 30*$day_secs;
    @myTimeLimits = ('TIME_LIMIT','PRI1_TIME_LIMIT','PRI2_TIME_LIMIT','PRI3_TIME_LIMIT','PRI4_TIME_LIMIT');
    foreach $tlimit (@myTimeLimits) {
	if ($GAR_Settings{$tlimit} eq "mins") {
	    if ($tlimit eq 'TIME_LIMIT') {
		$timelimit = $GAR_Settings{'TIME_QTY'}*$min_secs;
	    } elsif ($tlimit eq 'PRI1_TIME_LIMIT') {
		$timelimit1 = $GAR_Settings{'PRI1_TIME_QTY'}*$min_secs;
	    } elsif ($tlimit eq 'PRI2_TIME_LIMIT') {
		$timelimit2 = $GAR_Settings{'PRI2_TIME_QTY'}*$min_secs;
	    } elsif ($tlimit eq 'PRI3_TIME_LIMIT') {
		$timelimit3 = $GAR_Settings{'PRI3_TIME_QTY'}*$min_secs;
	    } elsif ($tlimit eq 'PRI4_TIME_LIMIT') {
		$timelimit4 = $GAR_Settings{'PRI4_TIME_QTY'}*$min_secs;
	    }
	} elsif ($GAR_Settings{$tlimit} eq "hrs") {
	    if ($tlimit eq 'TIME_LIMIT') {
		$timelimit = $GAR_Settings{'TIME_QTY'}*$hour_secs;
	    } elsif ($tlimit eq 'PRI1_TIME_LIMIT') {
		$timelimit1 = $GAR_Settings{'PRI1_TIME_QTY'}*$hour_secs;
	    } elsif ($tlimit eq 'PRI2_TIME_LIMIT') {
		$timelimit2 = $GAR_Settings{'PRI2_TIME_QTY'}*$hour_secs;
	    } elsif ($tlimit eq 'PRI3_TIME_LIMIT') {
		$timelimit3 = $GAR_Settings{'PRI3_TIME_QTY'}*$hour_secs;
	    } elsif ($tlimit eq 'PRI4_TIME_LIMIT') {
		$timelimit4 = $GAR_Settings{'PRI4_TIME_QTY'}*$hour_secs;
	    }
	} elsif ($GAR_Settings{$tlimit} eq "days") {
	    if ($tlimit eq 'TIME_LIMIT') {
		$timelimit = $GAR_Settings{'TIME_QTY'}*$day_secs;
	    } elsif ($tlimit eq 'PRI1_TIME_LIMIT') {
		$timelimit1 = $GAR_Settings{'PRI1_TIME_QTY'}*$day_secs;
	    } elsif ($tlimit eq 'PRI2_TIME_LIMIT') {
		$timelimit2 = $GAR_Settings{'PRI2_TIME_QTY'}*$day_secs;
	    } elsif ($tlimit eq 'PRI3_TIME_LIMIT') {
		$timelimit3 = $GAR_Settings{'PRI3_TIME_QTY'}*$day_secs;
	    } elsif ($tlimit eq 'PRI4_TIME_LIMIT') {
		$timelimit4 = $GAR_Settings{'PRI4_TIME_QTY'}*$day_secs;
	    }
	} elsif ($GAR_Settings{$tlimit} eq "wks") {
	    if ($tlimit eq 'TIME_LIMIT') {
		$timelimit = $GAR_Settings{'TIME_QTY'}*$week_secs;
	    } elsif ($tlimit eq 'PRI1_TIME_LIMIT') {
		$timelimit1 = $GAR_Settings{'PRI1_TIME_QTY'}*$week_secs;
	    } elsif ($tlimit eq 'PRI2_TIME_LIMIT') {
		$timelimit2 = $GAR_Settings{'PRI2_TIME_QTY'}*$week_secs;
	    } elsif ($tlimit eq 'PRI3_TIME_LIMIT') {
		$timelimit3 = $GAR_Settings{'PRI3_TIME_QTY'}*$week_secs;
	    } elsif ($tlimit eq 'PRI4_TIME_LIMIT') {
		$timelimit4 = $GAR_Settings{'PRI4_TIME_QTY'}*$week_secs;
	    }
	} elsif ($GAR_Settings{$tlimit} eq "mons") {
	    if ($tlimit eq 'TIME_LIMIT') {
		$timelimit = $GAR_Settings{'TIME_QTY'}*$month_secs;
	    } elsif ($tlimit eq 'PRI1_TIME_LIMIT') {
		$timelimit1 = $GAR_Settings{'PRI1_TIME_QTY'}*$month_secs;
	    } elsif ($tlimit eq 'PRI2_TIME_LIMIT') {
		$timelimit2 = $GAR_Settings{'PRI2_TIME_QTY'}*$month_secs;
	    } elsif ($tlimit eq 'PRI3_TIME_LIMIT') {
		$timelimit3 = $GAR_Settings{'PRI3_TIME_QTY'}*$month_secs;
	    } elsif ($tlimit eq 'PRI4_TIME_LIMIT') {
		$timelimit4 = $GAR_Settings{'PRI4_TIME_QTY'}*$month_secs;
	    }
	} elsif ($GAR_Settings{$tlimit} eq "no limit") {
	    if ($tlimit eq 'TIME_LIMIT') {
		$timelimit = 99999999;
	    } elsif ($tlimit eq 'PRI1_TIME_LIMIT') {
		$timelimit1 = 99999999;
	    } elsif ($tlimit eq 'PRI2_TIME_LIMIT') {
		$timelimit2 = 99999999;
	    } elsif ($tlimit eq 'PRI3_TIME_LIMIT') {
		$timelimit3 = 99999999;
	    } elsif ($tlimit eq 'PRI4_TIME_LIMIT') {
		$timelimit4 = 99999999;
	    }
	}
    }
    open(FILE, "$GAR_Conf_file") or die "Unable to open $GAR_Conf_file for input.";
    my @temp = <FILE>;
    close FILE;
    my $line;
    my @split;
    open(FILE, ">$GAR_Conf_file") or die "Unable to open $GAR_Conf_file for output.";
    foreach $line (@temp) {
	chomp $line;
	@split = split(/\t+/, $line);
	if ($split[0] eq "TimeLimit") {
	    print FILE "TimeLimit\t$timelimit\n";
	} elsif ($split[0] eq "Pri1TimeLimit") {
	    print FILE "Pri1TimeLimit\t$timelimit1\n";
	} elsif ($split[0] eq "Pri2TimeLimit") {
	    print FILE "Pri2TimeLimit\t$timelimit2\n";
	} elsif ($split[0] eq "Pri3TimeLimit") {
	    print FILE "Pri3TimeLimit\t$timelimit3\n";
	} elsif ($split[0] eq "Pri4TimeLimit") {
	    print FILE "Pri4TimeLimit\t$timelimit4\n";
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
	    my $sids = $GAR_Settings{'SIDS'};
	    my @sids = split (/\n/, $sids);
	    foreach $line (@sids) {
		my @temp1 = split (/\s+/, $line);
		if ($temp1[0] eq "\#") {
		    shift (@sids);
		}
	    }
	    shift (@sids);
	    my $sidstring = join (",", @sids);
	    print FILE "IgnoreSIDs\t$sidstring\n";
	} elsif ($split[0] eq "IgnoreGIDs") {
	    my $gids = $GAR_Settings{'GIDS'};
	    my @gids = split (/\n/, $gids);
	    foreach $line (@gids) {
		my @temp1 = split (/\s+/, $line);
		if ($temp1[0] eq "\#") {
		    shift (@gids);
		}
	    }
	    shift (@gids);
	    my $gidstring = join (",", @gids);
	    print FILE "IgnoreGIDs\t$gidstring\n";
	} else {
	    print FILE "$line\n";
	}
    }
    close FILE;
    &writehash("$GAR_Settings_file", \%GAR_Settings);
}

if ( defined $GAR_Settings{'ACTION'} and $GAR_Settings{'ACTION'} eq $tr{'add'} ) {
    my $ip = $GAR_Settings{'IP'};
    my $comment = $GAR_Settings{'COMMENT'};
	
    unless(&validipormask($ip)) { $errormessage = $tr{'source ip bad'}; }
    my $srcname = gethostbyaddr(inet_aton($ip), AF_INET);
    if ($srcname eq '') {
	$srcname = $ip;
    }

    unless ($errormessage) {
	open (FILE,">>$GAR_Ignore_IP_details") or die 'Unable to open config file for output.';
	flock FILE, 2;
	print FILE "$ip,$srcname,$comment,on\n";
	close (FILE);

	open (TEMP, ">>$GAR_Ignore_IP") or die 'Unable to open ignore file for output.';
	flock TEMP, 2;
	print TEMP "$ip\n";
	close TEMP;
    }
    &writehash("$GAR_Settings_file", \%GAR_Settings);
}

if ( defined $GAR_Settings{'ACTION'} and $GAR_Settings{'ACTION'} eq $tr{'remove'} 
or $GAR_Settings{'ACTION'} eq $tr{'edit'}) {
    open(FILE, "$GAR_Ignore_IP_details") or die 'Unable to open ignore config file for input.';
    my @current = <FILE>;
    close(FILE);

    foreach $line (@current) {
	$id++;
	if ($GAR_Settings{$id} eq "on") {
	    $count++; 
	}
    }

    if ($count == 0) {
	$errormessage = $tr{'nothing selected'};
    }
    if ($count > 1 && $GAR_Settings{'ACTION'} eq $tr{'edit'}) {
	$errormessage = $tr{'you can only select one item to edit'}; 
    }
	
    unless ($errormessage) {
	open(FILE, ">$GAR_Ignore_IP_details") or die 'Unable to open config file for output.';
	flock FILE, 2;
	$id = 0;
	foreach $line (@current) {
	    $id++;
	    unless ($GAR_Settings{$id} eq "on") {
		print FILE "$line"; 
	    } elsif ($GAR_Settings{'ACTION'} eq $tr{'edit'}) {
		chomp $line;
		my @temp2 = split(/\,/, $line);
		$GAR_Settings{'IP'} = $temp2[0];
		$GAR_Settings{'COMMENT'} = $temp2[2];
	    }
	}
	close(FILE);

	open(FILE, $GAR_Ignore_IP_details) or die 'Unable to open config file for input.';
	@current = <FILE>;
	close FILE;

	open(FILE, ">$GAR_Ignore_IP") or die 'Unable to open ignore file for output.';
	foreach $line (@current) {
	    @split = split(/\,/, $line);
	    print FILE "$split[0]\n";
	}
	close FILE;
    }
    &writehash("$GAR_Settings_file", \%GAR_Settings);
}


my @temp;
my @split;
my $line;
my $splitline;

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

&alertbox($errormessage);

print "<FORM METHOD='POST'>\n";

&openbox($tr{'gar2'});
print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD WIDTH='20%' CLASS='base'>$tr{'enabled'}</TD>
	<TD WIDTH='5%'><INPUT TYPE='checkbox' NAME='ENABLE_GUARD' $checked{'ENABLE_GUARD'}{'on'}><INPUT TYPE='hidden' NAME='GUARD_STATE' VALUE='$GAR_Settings{'GUARD_STATE'}'></TD>
	<TD WIDTH='45%'>&nbsp;</TD>
	<TD WIDTH='25%' CLASS='base'>Guardian $guard_ver</TD>
    </TR>
    <TR>
	<TD WIDTH='70%' COLSPAN='3'>&nbsp;</TD>
	<TD WIDTH='25%' CLASS='base'>Snort $snortDisplayversion</TD>
    </TR>
    <TR>
	<TD WIDTH='70%' COLSPAN='3'>&nbsp;</TD>
	<TD WIDTH='30%' ><A HREF='gartool.cgi'><FONT COLOR='blue'>$tr{'gartool link'}</FONT></A></TD>
    </TR>
</TABLE>
END

print <<END;
<DIV ALIGN='CENTER'>
    <TABLE WIDTH='60%'>
	<TR>
	    <TD WIDTH='50%' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'save'}'></TD>
	</TR>
    </TABLE>
</DIV>
<BR>
END
&closebox();

&openbox($tr{'gar settings'});
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
	<TD COLSPAN='6' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    &nbsp;&nbsp;Default: 
	    <SELECT TYPE='MENU' NAME='TIME_QTY'>
END
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='TIME_LIMIT'>
END
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    Minimum Priority: 
	    <SELECT TYPE='MENU' NAME='MIN_PRIOR'>
END
	foreach (@min) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'MIN_PRIOR'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    Priority 1: 
	    <SELECT TYPE='MENU' NAME='PRI1_TIME_QTY'>
END
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI1_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI1_TIME_LIMIT'>
END
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI1_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    Maximum Priority:
	    <SELECT TYPE='MENU' NAME='MAX_PRIOR'>
END
	foreach (@max) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'MAX_PRIOR'}{$_}>$_</OPTION>\n";
	}
	print <<END;
 	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    Priority 2:
	    <SELECT TYPE='MENU' NAME='PRI2_TIME_QTY'>
END
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI2_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI2_TIME_LIMIT'>
END
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI2_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    Empty Priority: 
	    <SELECT TYPE='MENU' NAME='MT_PRIOR'>
		<OPTION VALUE='yes' $selected{'MT_PRIOR'}{yes}>yes</OPTION>
		<OPTION VALUE='no' $selected{'MT_PRIOR'}{no}>no</OPTION>
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    Priority 3: 
	    <SELECT TYPE='MENU' NAME='PRI3_TIME_QTY'>
END
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI3_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI3_TIME_LIMIT'>
END
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI3_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    Log Hits:
	    <SELECT TYPE='MENU' NAME='FORCE_LOG'>
		<OPTION VALUE='yes' $selected{'FORCE_LOG'}{yes}>yes</OPTION>
		<OPTION VALUE='no' $selected{'FORCE_LOG'}{no}>no</OPTION>
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='CENTER'>
	    Priority 4: 
	    <SELECT TYPE='MENU' NAME='PRI4_TIME_QTY'>
END
	foreach (@timeqty) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI4_TIME_QTY'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	    <SELECT TYPE='MENU' NAME='PRI4_TIME_LIMIT'>
END
	foreach (@timefmt) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'PRI4_TIME_LIMIT'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
	<TD ALIGN='RIGHT'>
	    Log message level: 
	    <SELECT TYPE='MENU' NAME='LOG_LVL'>
END
	foreach (@loglvl) {
	    print "\t\t\t\t<OPTION VALUE='$_' $selected{'LOG_LVL'}{$_}>$_</OPTION>\n";
	}
	print <<END;
	    </SELECT>
	</TD>
	<TD WIDTH='13%'>&nbsp;</TD>
    </TR>
    <TR>
	<TD COLSPAN='6' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
</TABLE>
END
&closebox();

&openbox($tr{'gar snort and group ids'});
print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD COLSPAN='3' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar ignored sids'}</B></TD>
	<TD WIDTH='10%' ALIGN='CENTER'>&nbsp;</TD>
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar ignored gids'}</B></TD>
    </TR>
    <TR>
	<TD COLSPAN='3' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD ALIGN='CENTER' VALIGN='TOP'><TEXTAREA NAME='SIDS' COLS='25' ROWS='15'>
END
    my $line;
    my $id = 0;
    my (@split, @resplit);
    open(FILE, "$GAR_Conf_file") or die "Unable to open $GAR_Conf_file for input.";
    @temp = <FILE>;
    close FILE;

    print "# Enter one SID per line\n";
    print "# in GID:SID format\n";
    print "# for example 125:7\n";
    print "# HELP LINK AT TOP RIGHT!\n";
    foreach $line (@temp) {
	chomp $line;
	@split = split(/\t+/, $line);
	if ($split[0] eq "IgnoreSIDs") {
	    @resplit = split (/\,/, $split[1]);
	    foreach $sid (@resplit) {
		print "$resplit[$id]\n";
		$id++;
	    }
	}
    }

print <<END;
</TEXTAREA></TD>
	<TD WIDTH='10%' ALIGN='CENTER'>&nbsp;</TD>
	<TD ALIGN='CENTER' VALIGN='TOP'><TEXTAREA NAME='GIDS' COLS='25' ROWS='15'>
END

    $id = 0;
    print "# Enter one GID per line\n";
    print "# for example 125\n";
    print "# HELP LINK AT TOP RIGHT!\n";
    foreach $line (@temp) {
	chomp $line;
	@split = split(/\t+/, $line);
	if ($split[0] eq "IgnoreGIDs") {
	    @resplit = split (/\,/, $split[1]);
	    foreach $sid (@resplit) {
		print "$resplit[$id]\n";
		$id++;
	    }
	}
    }

print <<END;
</TEXTAREA></TD>
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
&closebox();

&openbox($tr{'gar ignored ips'});
print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD COLSPAN='4' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD ALIGN='CENTER'>$tr{'gar ip to ignore'}</TD>
	<TD ALIGN='LEFT'><INPUT TYPE='text' NAME='IP' VALUE='$GAR_Settings{'IP'}' SIZE='30'></TD>
	<TD ALIGN='CENTER'>$tr{'gar comment'}</TD>
	<TD ALIGN='LEFT'><INPUT TYPE='text' NAME='COMMENT' VALUE='$GAR_Settings{'COMMENT'}' SIZE='50'></TD>
    </TR>
    <TR>
	<TD COLSPAN='4' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD COLSPAN='4' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'add'}'></TD>
    </TR>
</TABLE>
END

print qq{
<!--
QUERY_STRING: "$ENV{'QUERY_STRING'}"
ORDER: "$GAR_Settings{'ORDER'}"
COLUMN: "$GAR_Settings{'COLUMN'}"
-->
<TABLE WIDTH='100%'>
    <TR>
	<TD COLSPAN='2' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD COLSPAN='2' ALIGN='CENTER'>
};

my %render_settings = 
(
#	'url'     => "$tr{'ssgar'}.cgi?[%COL%],[%ORD%],$GAR_Settings{'COLUMN_TWO'},$GAR_Settings{'ORDER_TWO'}",
	'url'     => "$tr{'ssgar'}.cgi?[%COL%],[%ORD%]",
	'columns' => [ 
		{ 
			column => '1',
			title  => 'Ignore IP',
			size   => 30,
			sort   => \&ipcompare,
		},
		{
			column => '2',
			title  => 'Hostname',
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

&displaytable( $GAR_Ignore_IP_details, \%render_settings, $GAR_Settings{'ORDER'}, $GAR_Settings{'COLUMN'} );

print <<END;
	</TD>
    </TR>
    <TR>
	<TD COLSPAN='2' ALIGN='CENTER'>&nbsp;</TD>
    </TR>
    <TR>
	<TD WIDTH='50%' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'remove'}'></TD>
	<TD WIDTH='50%' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'edit'}'></TD>
    </TR>
</TABLE>
<BR>
END
&closebox();

&alertbox('add','add');

print "</FORM>\n";

&closebigbox();

# close except </body> and </html>
&closepage( "update" );

print <<END;
</body>
</html>
END
