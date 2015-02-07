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

&showhttpheaders();

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
my $errormessage = '';

&readhash("$GAR_Settings_file",\%GAR_Settings);
&writehash("$GAR_Home_dir/hash-test1",\%GAR_Settings);
&getcgihash(\%GAR_Settings);
my $GAR_sids = $GAR_Settings{'SIDS'};
my $GAR_gids = $GAR_Settings{'GIDS'};
chomp($GAR_sids);
chomp($GAR_gids);
$GAR_sids =~ s/\n/,/g;
$GAR_gids =~ s/\n/,/g;
$GAR_Settings{'SIDS'} = $GAR_sids;
$GAR_Settings{'GIDS'} = $GAR_gids;
&writehash("$GAR_Home_dir/hash-test2",\%GAR_Settings);

open(FILE, ">$GAR_Home_dir/sid-test") or die "Unable to open $GAR_Home_dir/sid-test for input.";
print FILE "GAR_sids = \"$GAR_sids\"\n";
print FILE "GAR_Settings{'SIDS'} = \"$GAR_Settings{'SIDS'}\"\n";
close FILE;
open(FILE, ">$GAR_Home_dir/gid-test") or die "Unable to open $GAR_Home_dir/gid-test for input.";
print FILE "GAR_gids = \"$GAR_gids\"\n";
print FILE "GAR_Settings{'GIDS'} = \"$GAR_Settings{'GIDS'}\"\n";
close FILE;



&openpage('TEST', 1, '', 'services');

&openbigbox('100%', 'LEFT');

&alertbox($errormessage);

&openbox('POST RESULTS');
print <<END;
<TABLE WIDTH='100%' border='1'>
    <TR>
	<TD>GAR_sids</TD>
	<TD>"$GAR_sids"</TD>
    </TR>
    <TR>
	<TD>GAR_Settings{'SIDS'}</TD>
	<TD>"$GAR_Settings{'SIDS'}"</TD>
    </TR>
    <TR>
	<TD>GAR_gids</TD>
	<TD>"$GAR_gids"</TD>
    </TR>
    <TR>
	<TD>GAR_Settings{'GIDS'}</TD>
	<TD>"$GAR_Settings{'GIDS'}"</TD>
    </TR>
</TABLE>
END
&closebox();



print "<FORM METHOD='POST'>\n";

&openbox('TEXTAREA TEST');
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
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar sid rules'}</B></TD>
	<TD WIDTH='10%' ALIGN='CENTER'>&nbsp;</TD>
	<TD WIDTH='30%' ALIGN='CENTER'><B>$tr{'gar gid rules'}</B></TD>
    </TR>
    <TR>
	<TD ALIGN='CENTER' VALIGN='TOP'>
	    <TEXTAREA NAME='SIDS' COLS='25' ROWS='15'>
END
    my @mysplit;
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
        <TD WIDTH='10%' ALIGN='CENTER'>&nbsp;</TD>
	<TD ALIGN='CENTER' VALIGN='TOP'>
	    <TEXTAREA NAME='GIDS' COLS='25' ROWS='15'>
END

    @mysplit = split(/\,/, $GAR_Settings{'GIDS'});
    foreach $gid (@mysplit) {
	chomp($gid);
	$gid =~ s/^\s+//;
	$gid =~ s/\s+$//;
	if (length($gid) > 0) {
	    print "$gid\n";
	}
    }

print <<END;
</TEXTAREA>
	</TD>
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

print "</FORM>\n";

&closebigbox();

&closepage();
