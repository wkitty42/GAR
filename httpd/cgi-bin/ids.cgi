#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );
use File::Find;
use Cwd;

my (%snortsettings, %checked);
my $VRTC_ruleage_f = "${swroot}/snort/VRTC_ruleage";
my $VRT_ruleage_f = "${swroot}/snort/VRT_ruleage";
my $ET_ruleage_f = "${swroot}/snort/ET_ruleage";
@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
@weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);
&showhttpheaders();

$snortsettings{'ENABLE_SNORT'} = 'off';
$snortsettings{'ENABLE_VRT'} = 'off';
$snortsettings{'VRT_AUTOUPDATE'} = 'off';
#$snortsettings{'VRT_SUBSCRIBER'} = 'off';
$snortsettings{'ENABLE_VRTC'} = 'off';
$snortsettings{'VRTC_AUTOUPDATE'} = 'off';
$snortsettings{'ENABLE_ET'} = 'off';
$snortsettings{'ET_AUTOUPDATE'} = 'off';
$snortsettings{'ACTION'} = '';
&getcgihash(\%snortsettings);

$errormessage = '';
if ($snortsettings{'ACTION'} eq $tr{'save and update rules'})
{
	if (($snortsettings{'ENABLE_VRT'} eq 'on') and ($snortsettings{'OINK'} !~ /^([\da-f]){40}$/i))
	{
		$errormessage = $tr{'oink code must be 40 hex digits'};
		goto EXIT;
	}
	&writehash("${swroot}/snort/settings", \%snortsettings);
	EXIT:
}
if (($snortsettings{'ACTION'} eq $tr{'save'}) or 
   ($snortsettings{'ACTION'} eq $tr{'save and update rules'})) {

	&writehash("${swroot}/snort/settings", \%snortsettings);

	if ($snortsettings{'ENABLE_SNORT'} eq 'on') {
		&log($tr{'snort is enabled'}); }
	else {
		&log($tr{'snort is disabled'}); }

	my $success = message('snortrestart');

	if (not defined $success) {
		$errormessage = $tr{'smoothd failure'};
		goto EXIT;
	}

	if ($snortsettings{'VRT_AUTOUPDATE'} eq 'on') {
		&log($tr{'VRT is enabled'});
		my $success = message('addVRTautoupdate'); }
	else {
		&log($tr{'VRT is disabled'});
		my $success = message('delVRTautoupdate'); }

	if (not defined $success) {
		$errormessage = $tr{'smoothd failure'};
		goto EXIT;
	}

	if ($snortsettings{'VRTC_AUTOUPDATE'} eq 'on') {
		&log($tr{'VRTC is enabled'});
		my $success = message('addVRTCautoupdate'); }
	else {
		&log($tr{'VRTC is disabled'});
		my $success = message('delVRTCautoupdate'); }

	if (not defined $success) {
		$errormessage = $tr{'smoothd failure'};
		goto EXIT;
	}

	if ($snortsettings{'ET_AUTOUPDATE'} eq 'on') {
		&log($tr{'ET is enabled'});
		my $success = message('addETautoupdate'); }
	else {
		&log($tr{'ET is disabled'});
		my $success = message('delETautoupdate'); }

	if (not defined $success) {
		$errormessage = $tr{'smoothd failure'};
		goto EXIT;
	}
}

&readhash("${swroot}/snort/settings", \%snortsettings);

$checked{'ENABLE_SNORT'}{'off'} = '';
$checked{'ENABLE_SNORT'}{'on'} = '';
$checked{'ENABLE_SNORT'}{$snortsettings{'ENABLE_SNORT'}} = 'CHECKED';
$checked{'ENABLE_VRT'}{'off'} = '';
$checked{'ENABLE_VRT'}{'on'} = '';
$checked{'ENABLE_VRT'}{$snortsettings{'ENABLE_VRT'}} = 'CHECKED';
$checked{'VRT_AUTOUPDATE'}{'off'} = '';
$checked{'VRT_AUTOUPDATE'}{'on'} = '';
$checked{'VRT_AUTOUPDATE'}{$snortsettings{'VRT_AUTOUPDATE'}} = 'CHECKED';
#$checked{'VRT_SUBSCRIBER'}{'off'} = '';
#$checked{'VRT_SUBSCRIBER'}{'on'} = '';
#$checked{'VRT_SUBSCRIBER'}{$snortsettings{'VRT_SUBSCRIBER'}} = 'CHECKED';
$checked{'ENABLE_VRTC'}{'off'} = '';
$checked{'ENABLE_VRTC'}{'on'} = '';
$checked{'ENABLE_VRTC'}{$snortsettings{'ENABLE_VRTC'}} = 'CHECKED';
$checked{'VRTC_AUTOUPDATE'}{'off'} = '';
$checked{'VRTC_AUTOUPDATE'}{'on'} = '';
$checked{'VRTC_AUTOUPDATE'}{$snortsettings{'VRTC_AUTOUPDATE'}} = 'CHECKED';
$checked{'ENABLE_ET'}{'off'} = '';
$checked{'ENABLE_ET'}{'on'} = '';
$checked{'ENABLE_ET'}{$snortsettings{'ENABLE_ET'}} = 'CHECKED';
$checked{'ET_AUTOUPDATE'}{'off'} = '';
$checked{'ET_AUTOUPDATE'}{'on'} = '';
$checked{'ET_AUTOUPDATE'}{$snortsettings{'ET_AUTOUPDATE'}} = 'CHECKED';


my $VRTC_ruleage = 'N/A';
my $VRTC_lastupdate = 'N/A';
if (-e "$VRTC_ruleage_f")
{
    $t_stamp = -M "$VRTC_ruleage_f";
    if (int($t_stamp) == 0) {                         # it must be X hours
	$t_stamp = int($t_stamp * 24);
	if ($t_stamp == 1) {
	    $VRTC_ruleage = "$tr{'one hour'}";
	} else {
	    $VRTC_ruleage = "$t_stamp $tr{'hours'}";
	}
    } elsif (int($t_stamp) == 1) {                    # it must be X days
	$VRTC_ruleage = "$tr{'one day'}";
    } else {
	$t_stamp = int($t_stamp);
	$VRTC_ruleage = "$t_stamp $tr{'days'}";
    }
    open (MY_INPUT,"$VRTC_ruleage_f");
    $VRTC_lastupdate = <MY_INPUT>;
    close (MY_INPUT);
    chomp($VRTC_lastupdate);
}


my $VRT_ruleage = 'N/A';
my $VRT_lastupdate = 'N/A';
if (-e "$VRT_ruleage_f")
{
    $t_stamp = -M "$VRT_ruleage_f";
    if (int($t_stamp) == 0) {                         # it must be X hours
	$t_stamp = int($t_stamp * 24);
	if ($t_stamp == 1) {
	    $VRT_ruleage = "$tr{'one hour'}";
	} else {
	    $VRT_ruleage = "$t_stamp $tr{'hours'}";
	}
    } elsif (int($t_stamp) == 1) {                    # it must be X days
	$VRT_ruleage = "$tr{'one day'}";
    } else {
	$t_stamp = int($t_stamp);
	$VRT_ruleage = "$t_stamp $tr{'days'}";
    }
    open (MY_INPUT,"$VRT_ruleage_f");
    $VRT_lastupdate = <MY_INPUT>;
    close (MY_INPUT);
    chomp($VRT_lastupdate);
}



my $ET_ruleage = 'N/A';
my $ET_lastupdate = 'N/A';
if (-e "$ET_ruleage_f")
{
    $t_stamp = -M "$ET_ruleage_f";
    if (int($t_stamp) == 0) {                         # it must be X hours
	$t_stamp = int($t_stamp * 24);
	if ($t_stamp == 1) {
	    $ET_ruleage = "$tr{'one hour'}";
	} else {
	    $ET_ruleage = "$t_stamp $tr{'hours'}";
	}
    } elsif (int($t_stamp) == 1) {                    # it must be X days
	$ET_ruleage = "$tr{'one day'}";
    } else {
	$t_stamp = int($t_stamp);
	$ET_ruleage = "$t_stamp $tr{'days'}";
    }
    open (MY_INPUT,"$ET_ruleage_f");
    $ET_lastupdate = <MY_INPUT>;
    close (MY_INPUT);
    chomp($ET_lastupdate);
}

# start snort version query
open (MY_INPUT,"/usr/bin/snort -V 2>&1 |");
while (<MY_INPUT>)
{
    chomp;
    if (/Version\s+(.*)/)
    {
	($snortDisplayversion, $sub1, $sub2, $sub3, $sub4) = split(/ /,$1);
	($ETver1, $ETver2, $ETver3, $ETver4, ) = split(/\./,$snortDisplayversion);
	$snortETversion = join('.', $ETver1, $ETver2, $ETver3);
	$snortVRTversion = $snortDisplayversion;
	$snortVRTversion =~ s/\.//g;
	$snortDisplayversion = $snortDisplayversion . " $sub1 $sub2 $sub3 $sub4";
    }
}
while (length($snortVRTversion) < 4) {
    # ensure that the version is four characters long for the VRT url
    $snortVRTversion = $snortVRTversion . '0'; }
#if ($snortsettings{'VRT_SUBSCRIBER'} eq 'on') {
#    # add the VRT paying subscriber indicator to the end of the version
#    $snortVRTversion = $snortVRTversion . '_s'; }
# end snort version query

&openpage($tr{'intrusion detection system'}, 1, '', 'services');

&openbigbox('100%', 'LEFT');

&alertbox($errormessage);

# debug: print the snortsettings hash keys and values
#while (($key,$value) = each(%snortsettings)){
#  print $key." = ".$value."<br />\n";
#}

print "<FORM METHOD='POST'>\n";

&openbox($tr{'intrusion detection system2'});
print <<END;
<TABLE WIDTH='100%'>
<TR>
	<TD WIDTH='18%' CLASS='base'>$tr{'enabled'}</TD>
	<TD WIDTH='5%'><INPUT TYPE='checkbox' NAME='ENABLE_SNORT' $checked{'ENABLE_SNORT'}{'on'}></TD>
	<TD WIDTH='45%'>&nbsp;</TD>
	<TD WIDTH='25%' ALIGN='RIGHT'>Snort $snortDisplayversion </TD>
	<TD WIDTH='7%' ALIGN='LEFT'>[$snortVRTversion]</TD>
</TR>
</TABLE>
END
&closebox();

print <<END;
<DIV ALIGN='CENTER'>
<TABLE WIDTH='60%'>
<TR>
	<TD ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'save'}'></TD> 
</TR>
</TABLE>
</DIV>
END


&openbox($tr{'rule retreval'});
&openbox(); # sfvrt rules
print <<END;
<TABLE WIDTH='100%'>
<TR>
    <TD COLSPAN='2'><B>$tr{'sfvrt rules'}</B></TD>
    <TD COLSPAN='2'>&nbsp;</TD>
    <TD ALIGN='RIGHT'>$tr{'enabled'}</TD>
    <TD><INPUT TYPE='checkbox' NAME='ENABLE_VRT' $checked{'ENABLE_VRT'}{'on'}></TD>
</TR>
<TR>
    <TD WIDTH='15%'>$tr{'oink code'}</TD>
    <TD WIDTH='30%' COLSPAN='3' ALIGN='CENTER'><INPUT TYPE='text' NAME='OINK' SIZE='45' MAXLENGTH='40' VALUE='$snortsettings{OINK}' id='OINK' @{[jsvalidregex('OINK','^([0-9a-fA-F]){40}$')]}></TD>
END
#print <<END;
#    <TD WIDTH='20%' ALIGN='RIGHT'>$tr{'paid subscriber'}</TD>
#    <TD WIDTH='5%'><INPUT TYPE='checkbox' NAME='VRT_SUBSCRIBER' $checked{'VRT_SUBSCRIBER'}{'on'}></TD>
#END
print <<END;
    <TD WIDTH='20%'>&nbsp;</TD>
    <TD WIDTH='5%'>&nbsp;</TD>
END
print <<END;
</TR>
<TR>
    <TD WIDTH='15%'>$tr{'vrt rule age'}</TD>
    <TD WIDTH='10%'>$VRT_ruleage</TD>
    <TD WIDTH='20%' ALIGN='RIGHT'>$tr{'vrt last update'}</TD>
    <TD WIDTH='25%'>$VRT_lastupdate</TD>
    <TD WIDTH='20%' ALIGN='RIGHT'>$tr{'autoupd vrt'}</TD>
    <TD WIDTH='5%'><INPUT TYPE='checkbox' NAME='VRT_AUTOUPDATE' $checked{'VRT_AUTOUPDATE'}{'on'}></TD>
</TR>
</TABLE>
END
&closebox(); # sfvrt rules

&openbox(); # sfvrt community rules
print <<END;
<TABLE WIDTH='100%'>
<TR>
    <TD COLSPAN='2'><B>$tr{'sfvrtc rules'}</B></TD>
    <TD COLSPAN='2'>&nbsp;</TD>
    <TD ALIGN='RIGHT'>$tr{'enabled'}</TD>
    <TD><INPUT TYPE='checkbox' NAME='ENABLE_VRTC' $checked{'ENABLE_VRTC'}{'on'}></TD>
</TR>
<TR>
    <TD WIDTH='15%'>$tr{'vrtc rule age'}</TD>
    <TD WIDTH='10%'>$VRTC_ruleage</TD>
    <TD WIDTH='20%' ALIGN='RIGHT'>$tr{'vrtc last update'}</TD>
    <TD WIDTH='25%'>$VRTC_lastupdate</TD>
    <TD WIDTH='20%' ALIGN='RIGHT'>$tr{'autoupd vrtc'}</TD>
    <TD WIDTH='5%'><INPUT TYPE='checkbox' NAME='VRTC_AUTOUPDATE' $checked{'VRTC_AUTOUPDATE'}{'on'}></TD>
</TR>
</TABLE>
END
&closebox(); # sfvrt community rules

&openbox(); #et rules
print <<END;
<TABLE WIDTH='100%'>
<TR>
    <TD COLSPAN='2'><B>$tr{'et rules'}</B></TD>
    <TD COLSPAN='2'>&nbsp;</TD>
    <TD ALIGN='RIGHT'>$tr{'enabled'}</TD>
    <TD><INPUT TYPE='checkbox' NAME='ENABLE_ET' $checked{'ENABLE_ET'}{'on'}></TD>
</TR>
<TR>
    <TD WIDTH='15%'>$tr{'et rule age'}</TD>
    <TD WIDTH='10%'>$ET_ruleage</TD>
    <TD WIDTH='20%' ALIGN='RIGHT'>$tr{'et last update'}</TD>
    <TD WIDTH='25%'>$ET_lastupdate</TD>
    <TD WIDTH='20%' ALIGN='RIGHT'>$tr{'autoupd et'}</TD>
    <TD WIDTH='5%'><INPUT TYPE='checkbox' NAME='ET_AUTOUPDATE' $checked{'ET_AUTOUPDATE'}{'on'}></TD>
</TR>
</TABLE>
END
&closebox(); # et rules

&closebox(); # rules retrieval

&alertbox('add', 'add');

&openbox();
print <<END;
<table class='blank'>
<tr>

	<td id='progressbar'>
<table class='progressbar' style='width: 380px;'>
	<tr>
		<td id='progress' class='progressbar' style='width: 1px;'>&nbsp;</td>
		<td class='progressend'>&nbsp;</td>
	</tr>
</table>
	<span id='status'></span>
	</td>
	<td>&nbsp;</td>
	<td style='width: 350px;' style='text-align: right;'>
		<INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'save and update rules'}'>
	</td>

</tr>
</table>
END
&closebox();

print "</FORM>\n";

&closebigbox();

# close except </body> and </html>
&closepage( "update" );
	
if ($snortsettings{'ACTION'} eq $tr{'save and update rules'} and !$errormessage)
{
	# do the ET Rules sets update first if it is enabled
	if ($snortsettings{'ENABLE_ET'} eq 'on') {
	    my $r_file = 'ET';
#	    my $url = 'http://www.emergingthreats.net/rules/emerging.rules.tar.gz';
	    my $url = 'http://rules.emergingthreats.net/open-nogpl/snort-' . $snortETversion . '/emerging.rules.tar.gz';
	    &runoinkmaster($url,$r_file);
	    # store the current update time inside the ET ruleage file 
	    &get_the_time;
	    open (FILE, ">$ET_ruleage_f");
	    print FILE "$theTime";
	    close (FILE);
	    # locate the newest ET rule set file
	    # and set the ruleage file to the same timedate stamp
	    $newest_file = ET_get_newest("${swroot}/snort/rules");
	    ($a_stamp, $m_stamp) = (stat $newest_file)[8,9];
	    utime $a_stamp, $m_stamp, $ET_ruleage_f;
	}

	# do the VRT Community Rules sets update second if it is enabled
	if ($snortsettings{'ENABLE_VRTC'} eq 'on') {
	    my $r_file = 'VRTC';
	    my $url = 'https://s3.amazonaws.com/snort-org/www/rules/community/community-rules.tar.gz';
	    &runoinkmaster($url,$r_file);
	    # store the current update time inside the VRT ruleage file 
	    &get_the_time;
	    open (FILE, ">$VRTC_ruleage_f");
	    print FILE "$theTime";
	    close (FILE);
	    # locate the newest VRT rule set file
	    # and set the ruleage file to the same timedate stamp
	    $newest_file = VRTC_get_newest("${swroot}/snort/rules");
	    ($a_stamp, $m_stamp) = (stat $newest_file)[8,9];
	    utime $a_stamp, $m_stamp, $VRTC_ruleage_f;
	}

	# do the VRT Rules sets update last if it is enabled
	if ($snortsettings{'ENABLE_VRT'} eq 'on') {
	    my $r_file = 'VRT';
	    my $url = 'http://www.snort.org/pub-bin/oinkmaster.cgi/' . $snortsettings{'OINK'} . "/snortrules-snapshot-$snortVRTversion.tar.gz";
	    &runoinkmaster($url,$r_file);
	    # store the current update time inside the VRT ruleage file 
	    &get_the_time;
	    open (FILE, ">$VRT_ruleage_f");
	    print FILE "$theTime";
	    close (FILE);
	    # locate the newest VRT rule set file
	    # and set the ruleage file to the same timedate stamp
	    $newest_file = VRT_get_newest("${swroot}/snort/rules");
	    ($a_stamp, $m_stamp) = (stat $newest_file)[8,9];
	    utime $a_stamp, $m_stamp, $VRT_ruleage_f;
	}
	# end of rules sets updating code

	if (!$errormessage) {

		print <<END;
<script>
	document.getElementById('status').innerHTML = "Restarting snort...";
</script>
END
		my $success = message('snortrestart');

		if (not defined $success) {
			$errormessage = $tr{'smoothd failure'};
		}
	}
	if ($errormessage) {
		print <<END;
<script>
	document.getElementById('status').innerHTML = "$errormessage";
	document.getElementById('progress').style.width = "1px";
</script>
END
	} else {
		print <<END;
<script>
	document.getElementById('status').innerHTML = "All updates complete!";
	document.getElementById('progress').style.width = "${maxwidth}px";
	document.location = "ids.cgi";
</script>
END
	}
}
print <<END;
</body>
</html>
END

sub get_the_time {
    $theTime = '';
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

sub ET_get_newest {
    my $dir = shift;
    -d $dir or die "1 - GAR ids.cgi : '$dir' is not a directory...\n";
    my %files;
    File::Find::find (
	sub {
	    my $name = $File::Find::name;
	    if ($name =~ /.*\.rules/ &&
		$name =~ /emerging.*\.rules/ &&
		$name !~ /local\.rules/) {
		$files{$name} = (stat $name)[9] if -f $name;
	    }
	}, $dir
    );
    ( sort { $files{$a} <=> $files{$b} } keys %files )[-1];
}

sub VRTC_get_newest {
    my $dir = shift;
    -d $dir or die "2 - GAR ids.cgi : '$dir' is not a directory...\n";
    my %files;
    File::Find::find (
	sub {
	    my $name = $File::Find::name;
	    if ($name =~ /community\.rules/ && 
		$name !~ /emerging.*\.rules/ &&
		$name !~ /local\.rules/) {
		$files{$name} = (stat $name)[9] if -f $name;
	    }
	}, $dir
    );
    ( sort { $files{$a} <=> $files{$b} } keys %files )[-1];
}

sub VRT_get_newest {
    my $dir = shift;
    -d $dir or die "3 - GAR ids.cgi : '$dir' is not a directory...\n";
    my %files;
    File::Find::find (
	sub {
	    my $name = $File::Find::name;
	    if ($name =~ /.*\.rules/ && 
		$name !~ /emerging.*\.rules/ &&
		$name !~ /local\.rules/) {
		$files{$name} = (stat $name)[9] if -f $name;
	    }
	}, $dir
    );
    ( sort { $files{$a} <=> $files{$b} } keys %files )[-1];
}

sub runoinkmaster
{
	my ($v, $r_file) = @_;
# we are passing the url in $v now instead of the snort version because the
# snort version is found higher above and tacked into the proper url before
# we get here... and since we have two urls, one for each rules set, we pass
# which ever one we need... this allows us to add a third snort rules sets
# location if desired ;)
#	my $url = 'http://www.snort.org/pub-bin/oinkmaster.cgi/' . $snortsettings{'OINK'} . "/snortrules-snapshot-$v.tar.gz";

	my $curdir = getcwd;
	chdir "${swroot}/snort/";
	
	select STDOUT;
	$| = 1;

	my $pid = open(FD, '-|');
	if (!defined $pid) {
		$errormessage = $tr{'unable to fetch rules'};
	} elsif ($pid) {
		$errormessage = $tr{'rules not available'};

		my $maxwidth = 400;

		print <<END;
<script>
document.getElementById('status').innerHTML = "Downloading $r_file Rules sets, please wait...";
document.getElementById('progress').style.background = "#a0a0ff";
</script>
END
		while(<FD>)
		{
			$errormessage = '';
			if (/(\d{1,3})%/) {
				my $percent = $1;
				my $message;
				if ($percent == 100) {
					print <<END;
<script>
	document.getElementById('status').innerHTML = "Installing $r_file Rules sets, please wait...";
	document.getElementById('progress').style.width = "${maxwidth}px";
</script>
END
				} else {
#					$message = "Download $percent% complete";
					my $curwidth = $maxwidth * $percent/100;
					print <<END;
<script>
document.getElementById('progress').style.width = "${curwidth}px";
</script>
END
				}
			}
		}
		close(FD);

		if ($?) {
			$errormessage = $tr{'unable to fetch rules'}; } 
		else
		{
# we used to update the ruleage file here but with more than one rules sets to
# work with, we now have multiple separate ruleage files which are updated
# above after returning from runoinkmaster
#			open (FILE, ">${swroot}/snort/ruleage");
#			close (FILE);
		}
	} else {
		# so we see wget's output
		close(STDERR);
		open(STDERR, ">&STDOUT");

# use the passed url in $v on the oinkmaster command line instead of $url
# because we have multiple different rules sets and thus multiple different urls...
#		exec('/usr/bin/oinkmaster.pl', '-v', '-C',
#		'/usr/lib/smoothwall/oinkmaster.conf', '-o', 'rules', '-u', $url);
		exec('/usr/bin/oinkmaster.pl', '-v', '-C',
		'/usr/lib/smoothwall/oinkmaster.conf', '-o', 'rules', '-u', $v);
	}

	chdir $curdir;
}
