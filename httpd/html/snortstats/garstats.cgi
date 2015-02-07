#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team
#
#

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
my ${GAR_Script_file} = "${GAR_Home_dir}/usr/bin/GAR";
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
       (${SnortDisplayVersion}, ${sub1}, ${sub2}, ${sub3}) = split(/ /,$1);
       ${SnortDLVersion} = "${SnortDisplayVersion}";
       ${SnortDLVersion} =~ s/\.//g;
       ${SnortDisplayVersion} = "${SnortDisplayVersion} ${sub1} ${sub2} ${sub3}";
    }
}
close(MY_INPUT);
 
# Get guardian version
open(MY_INPUT,"${GAR_Script_file} -v |");
my ${appID} = <MY_INPUT>;
close MY_INPUT;
chomp ${appID};

&openpage('GAR Snort Stats');

&openbigbox('100%', 'LEFT');

&alertbox(${errormessage});

&openbox($tr{'gar2'});
    print("<TABLE WIDTH='100%'>");
    print("	<TR>");
    if ("$SWEprodvals{'VERSION'}" == "3.0") {
	print("		<TD WIDTH='25%' style='text-align: left; padding: 4pt .5em 4pt 1em;'><A style='color: blue;' HREF='/cgi-bin/mods/GAR/gar.cgi'>$tr{'garcfg link'}</A></TD>");
    } else {
	print("		<TD WIDTH='25%' style='text-align: left; padding: 4pt .5em 4pt 1em;'><A style='color: blue;' HREF='/mods/GAR/cgi-bin/gar.cgi'>$tr{'garcfg link'}</A></TD>");
    }
    print("		<TD WIDTH='25%' style='text-align: center; padding: 4pt .5em 4pt 1em;'>${appID}</TD>");
    print("		<TD WIDTH='25%' style='text-align: center; padding: 4pt .5em 4pt 1em;'>Snort ${SnortDisplayVersion}</TD>");
    if ("$SWEprodvals{'VERSION'}" == "3.0") {
	print("		<TD WIDTH='25%' style='text-align: right; padding: 4pt .5em 4pt 1em;'><A style='color: blue;' HREF='/cgi-bin/mods/GAR/gartool.cgi'>$tr{'gartool link'}</A></TD>");
    } else {
	print("		<TD WIDTH='25%' style='text-align: right; padding: 4pt .5em 4pt 1em;'><A style='color: blue;' HREF='/mods/GAR/cgi-bin/gartool.cgi'>$tr{'gartool link'}</A></TD>");
    }
    print("	</TR>");
    print("</TABLE>");
&closebox();

&openbox('GAR Snort Stats:');
print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='05mins.html'>5 Mins</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='10mins.html'>10 Mins</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='15mins.html'>15 Mins</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='20mins.html'>20 Mins</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='30mins.html'>30 Mins</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='45mins.html'>45 Mins</A></TD>
    </TR>
    <TR>
      <TD COLSPAN='6'><HR></TD>
    </TR>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='01hours.html'>1 Hour</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='02hours.html'>2 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='03hours.html'>3 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='04hours.html'>4 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='06hours.html'>6 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='08hours.html'>8 Hours</A></TD>
    </TR>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='12hours.html'>12 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='14hours.html'>14 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='16hours.html'>16 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='18hours.html'>18 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='20hours.html'>20 Hours</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='22hours.html'>22 Hours</A></TD>
    </TR>
    <TR>
      <TD COLSPAN='6'><HR></TD>
    </TR>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='01days.html'>1 Day</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='02days.html'>2 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='03days.html'>3 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='04days.html'>4 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='05days.html'>5 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='06days.html'>6 Days</A></TD>
    </TR>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='07days.html'>7 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='14days.html'>14 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='21days.html'>21 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='30days.html'>30 Days</A></TD>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='45days.html'>45 Days</A></TD>
        <TD CLASS='base' ALIGN='CENTER'><A HREF='60days.html'>60 Days</A></TD>
    </TR>
</TABLE>
END
;

&closebox();

print <<END;
<BR>
<TABLE WIDTH='100%'>
  <TR>
    <TD CLASS='base' ALIGN='CENTER'>GAR Snort Stats is based on thepigdoktor by JJ Cummings</TD>
  </TR>
</TABLE>
<BR>
END
;

&alertbox('add','add');

#print "</FORM>\n";

&closebigbox();

# close except </body> and </html>
&closepage( "update" );

print <<END;
</body>
</html>
END
;

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
