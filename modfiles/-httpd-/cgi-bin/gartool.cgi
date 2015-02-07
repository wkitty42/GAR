#!/usr/bin/perl
#
# Distributed under the terms of the GNU General Public License (GPL)
#
# GAR Snort Rules management Tool v0.3a
#
# Mark Lewis - wkitty42
#

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );

use Cwd;

my (%snortsettings, %checked);

my ${version} = 'GARTool v0.4';
my %cgiparams;
my ${count};
my ${line};
my ${foo1};
my ${foo2};
my ${foo3};
my ${foo4};
my ${Search_Results};
my @oinktemp;
my @sidmaptemp;
my ${errormessage} = '';
my ${mod_dir} = '/var/smoothwall/mods/GAR';
my ${conf_file} = ${mod_dir} . '/etc/gartool.conf';
my ${rules_loc} = '/var/smoothwall/snort/rules';
my ${local_rules_file} = ${rules_loc} . '/local.rules';
my ${sid_msg_map_file} = ${rules_loc} . '/sid-msg.map';
$cgiparams{'ACTION'} = '';
$cgiparams{'SEARCH'} = '';
${Search_Term} = '';
${Search_Results} = '';

sub trim($);
sub ltrim($);
sub rtrim($);
sub do_sidmap;

# Perl trim function to remove whitespace from the start and end of the string
sub trim($)
{
    my ${string} = shift;
    ${string} =~ s/^\s+//;
    ${string} =~ s/\s+$//;
    return ${string};
}
# Left trim function to remove leading whitespace
sub ltrim($)
{
    my ${string} = shift;
    ${string} =~ s/^\s+//;
    return ${string};
}
# Right trim function to remove trailing whitespace
sub rtrim($)
{
    my ${string} = shift;
    ${string} =~ s/\s+$//;
    return ${string};
}

sub do_sidmap
{
    open(MY_OUTPUT,">${sid_msg_map_file}");
    open(MY_INPUT,"$mod_dir}/usr/bin/smoothwall/create-sidmap.pl ${rules_loc}|");
    while(<MY_INPUT>) {
	my ${line} = $_;
	chomp(${line});
	print MY_OUTPUT ${line}, "\n";
    }
    close(MY_INPUT);
    close(MY_OUTPUT);
}

#unless (-e "/var/smoothwall/mods/oinktool/settings") { system('/bin/touch /var/smoothwall/mods/oinktool/settings'); }
unless (-e "${sid_msg_map_file}") { do_sidmap; }
unless (-e "${conf_file}") { system('/bin/touch', "${conf_file}"); }
unless (-e "${local_rules_file}") { system('/bin/touch', "${local_rules_file}"); }

&getcgihash(\%cgiparams);
&readhash("${swroot}/snort/settings", \%snortsettings);
${Search_Term} = "$cgiparams{'SEARCH_TERM'}";

&showhttpheaders();

# start snort version query
open(MY_INPUT,"/usr/bin/snort -V 2>&1 |");
while(<MY_INPUT>) {
    chomp;
    if (/Version\s+(.*)/i) {
	(${SnortDisplayVersion}, $sub1, $sub2, $sub3) = split(/ /,$1);
	${SnortDLVersion} = ${SnortDisplayVersion};
	${SnortDLVersion} =~ s/\.//g;
	${SnortDisplayVersion} = ${SnortDisplayVersion} . " $sub1 $sub2 $sub3";
    }
}
close(MY_INPUT);
while (length(${SnortDLVersion}) < 4) {
    # ensure that the version is four characters long for the VRT url
    ${SnortDLVersion} = ${SnortDLVersion} . '0'; }
if ($snortsettings{'VRT_SUBSCRIBER'} eq 'on') {
    # add the VRT paying subscriber indicator to the end of the version
    ${SnortDLVersion} = ${SnortDLVersion} . '_s'; }
# end of snort version query

if ($cgiparams{'ACTION'} eq $tr{'save modified rules'}) {
	@oinktemp="$cgiparams{'MODIFIED_RULES'}";
	open (FILE, "> ${conf_file}") or die "unable to open modified SIDs file";
	foreach ${line} (@oinktemp) {
		print FILE "${line}";
	}
	close FILE;
}

if ($cgiparams{'ACTION'} eq $tr{'save local.rules'}) {
	@oinktemp="$cgiparams{'LOCAL_RULES'}";
	open (FILE, "> ${local_rules_file}") or die "unable to open local.rules file";
	foreach ${line} (@oinktemp) {
	    print FILE "${line}";
	}
	close FILE;
}

if ($cgiparams{'ACTION'} eq $tr{'search phrase'}) {
    open (SIDLIST, "< ${sid_msg_map_file}") or die "unable to open sid-msg.map";
    while (<SIDLIST>) {
	chomp;
	(${foo1},${foo2},${foo3},${foo4}) = split /\|\|/,$_;
	${foo1} = trim(${foo1});
	${foo2} = trim(${foo2});
	if ((index(${foo1},${Search_Term}) gt -1) || (index(${foo2},${Search_Term}) gt -1)) {
	    if (index(${foo2},'DELETED') eq -1) {
        	${Search_Results} = ${Search_Results} . "\t\t<TR><TD ALIGN='RIGHT'>${foo1}</TD><TD>${foo2}</TD></TR>\n";
	    }
	}
    }
    close SIDLIST;
}

if ($cgiparams{'ACTION'} eq $tr{'reload snort'}) {
        my ${success} = message('snortrestart');
        if (not defined ${success}) {
            ${errormessage} = $tr{'smoothd failure'}; }
}

if ($cgiparams{'ACTION'} eq $tr{'run oinkmaster and reload snort'}) {
        if ($snortsettings{'OINK'} !~ /^([\da-f]){40}$/i)
	{
	    ${errormessage} = $tr{'oink code must be 40 hex digits'};
	    goto EXIT;
	}

        my ${curdir} = getcwd;
	chdir "${swroot}/snort/";
	# ET rules first if enabled
	if ($snortsettings{'ENABLE_ET'} eq 'on') {
	    my $r_file = 'ET';
	    my $url = 'http://www.emergingthreats.net/rules/emerging.rules.tar.gz';
	    if (open(FD, '-|') || exec('/usr/bin/oinkmaster.pl', '-C','/usr/lib/smoothwall/oinkmaster.conf', '-o', 'rules', '-u', $url))
	    {
		${errormessage} = $tr{'rules not available'};
		while(<FD>)
		{
		    ${errormessage} = '';
		    print STDERR $_;
		}
		close(FD);
	    } else {
		${errormessage} = $tr{'unable to fetch rules'}; 
	    }
	}
	if ($snortsettings{'ENABLE_VRT'} eq 'on') {
	    my $r_file = 'VRT';
	    my $url = 'http://www.snort.org/pub-bin/oinkmaster.cgi/' . $snortsettings{'OINK'} . "/snortrules-snapshot-${SnortDLVersion}.tar.gz";
	    if (open(FD, '-|') || exec('/usr/bin/oinkmaster.pl', '-C','/usr/lib/smoothwall/oinkmaster.conf', '-o', 'rules', '-u', $url))
	    {
		${errormessage} = $tr{'rules not available'};
		while(<FD>)
		{
		    ${errormessage} = '';
		    print STDERR $_;
		}
		close(FD);
	    } else {
		${errormessage} = $tr{'unable to fetch rules'}; 
	    }
	}
	chdir ${curdir};

	do_sidmap;

        my ${success} = message('snortrestart');

        if (not defined ${success}) {
            ${errormessage} = $tr{'smoothd failure'}; }
EXIT:
}

&openpage($tr{'gar tool'}, 1, '', 'tools');

&openbigbox('100%', 'LEFT');

&alertbox(${errormessage});


# Search sid-msg.map file
&openbox('Search');
print <<END;
    <FORM METHOD='POST'>
	<TABLE WIDTH='100%'>
	    <TR>
		<TD COLSPAN='2' ALIGN='CENTER'>
		    <INPUT TYPE="text" name="SEARCH_TERM" size="40" maxlength="255" value="${Search_Term}" style="font-size: 10pt; border-style: solid; border-color: #3B3B3B;">
		</TD>
	    </TR>
	    <TR>
		<TD COLSPAN='2' ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'search phrase'}'></TD>
	    </TR>
	</TABLE>
    </FORM>
END
&closebox();

# Display search results of sid-msg.map file
if ($cgiparams{'ACTION'} eq $tr{'search phrase'}) {
    &openbox('Search Results');
    print "\t<TABLE WIDTH='100%'>\n";
    print "\t\t<TR><TH>SID</TH><TH>Description</TH></TR>\n";
    print ${Search_Results};
    print "\t</TABLE>";
    &closebox();
}

&openbox('Rules Modification Editing Box');

print <<END;
    <FORM METHOD='POST'>
	<TABLE WIDTH='100%'>
	    <TR>
		<TD ALIGN='CENTER'>
		    <TEXTAREA NAME='MODIFIED_RULES' COLS='80' ROWS='24' WRAP='off'>
END
open (DISPRULES, "< ${conf_file}") or die "unable to open rules modified file, ${conf_file},";
while (<DISPRULES>) {
    chomp;
    print "$_\n";
}
close DISPRULES;
print <<END;
		    </TEXTAREA>
		</TD>
	    </TR>
	</TABLE>
	<TABLE WIDTH='100%'>
	    <TR>
		<TD ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'save modified rules'}'></TD>
		<TD ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'run oinkmaster and reload snort'}'></TD>
	    </TR>
	</TABLE>
    </FORM>
END
&closebox();

&openbox('local.rules Editing Box');

print <<END;
    <FORM METHOD='POST'>
	<TABLE WIDTH='100%'>
	    <TR>
		<TD ALIGN='CENTER'>
		    <TEXTAREA NAME='LOCAL_RULES' COLS='80' ROWS='24' WRAP='off'>
END
open (LOCLRULES, "< ${local_rules_file}") or die "unable to open local.rules file";
while (<LOCLRULES>) {
    chomp;
    print "$_\n";
}
close LOCLRULES;
print <<END;
		    </TEXTAREA>
		</TD>
	    </TR>
	</TABLE>
	<TABLE WIDTH='100%'>
	    <TR>
		<TD ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'save local.rules'}'></TD>
		<TD ALIGN='CENTER'><INPUT TYPE='submit' NAME='ACTION' VALUE='$tr{'reload snort'}'></TD>
	    </TR>
	</TABLE>
	<br />
	<table width='100%'>
	    <tr>
		<td align='right'><B>${version} w/ Snort ${SnortDisplayVersion}</B></td>
	    </tr>
	</table>
    </FORM>
END
&closebox();

&alertbox('add','add');

&closebigbox();

&closepage(); 
