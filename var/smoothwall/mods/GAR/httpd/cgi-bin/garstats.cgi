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

my (%GAR_Settings, %CGI_Settings, %checked);
my ${GAR_Home_dir} = "${swroot}/mods/GAR";
my ${GAR_Settings_file} = "${GAR_Home_dir}/settings";
my ${GAR_Ignore_IP_details} = "${GAR_Home_dir}/config";
my ${GAR_Ignore_IP} = "${GAR_Home_dir}/etc/GAR.ignore";
my ${GAR_Conf_file} = "${GAR_Home_dir}/etc/GAR.conf";
my ${GAR_Script_file} = "${GAR_Home_dir}/usr/bin/GAR";

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
open(FILE,"${GAR_Script_file} -v |");
my ${appID} = <FILE>;
close FILE;
chomp ${appID};

&openpage($tr{'gar'}, 1, '', 'services');

&openbigbox('100%', 'LEFT');

&alertbox(${errormessage});

&openbox($tr{'gar2'});
print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD WIDTH='33%' CLASS='base'>${appID}</TD>
	<TD WIDTH='33%' CLASS='base' ALIGN='CENTER'>Snort ${SnortDisplayVersion}</TD>
	<TD WIDTH='33%' ALIGN='CENTER'><A HREF='gartool.cgi'><FONT COLOR='blue'>$tr{'gartool link'}</FONT></A></TD>
    </TR>
</TABLE>
END

&closebox();


&openbox('GAR Links');
print <<END;
<TABLE WIDTH='100%'>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='/mods/GAR/snortstats/'>Snort Stats</A></TD>
    </TR>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='/mods/GAR/snortstats/'>Snort Stats</A></TD>
    </TR>
    <TR>
	<TD CLASS='base' ALIGN='CENTER'><A HREF='/mods/GAR/snortstats/'>Snort Stats</A></TD>
    </TR>
</TABLE>
END
;
&closebox();

&alertbox('add','add');

#print "</FORM>\n";

&closebigbox();

# close except </body> and </html>
&closepage( "update" );

print <<END;
</body>
</html>
END


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
