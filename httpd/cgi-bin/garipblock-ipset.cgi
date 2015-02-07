#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL

#
# (c) SmoothWall Ltd 2003
#
# 04/18/2004 - Drew S. Dupont
#  - Modified display for new GAR support and file format changes
# 04/22/2004 - Drew S. Dupont
#  - Modified editing to allow for enhanced edit/update of blocks
#    (i.e. edit entry w/o deleting, update current entry w/o changing place
#     in list, display item currently being edited)
# 04/26/2004 - Drew S. Dupont
#  - Modified removal to allow removal of GAR added blocked IP's from GAR
# 05/01/2004 - Drew S. Dupont
#  - Added ability to switch a GAR added IP to a manually added IP; when
#    switched, IP is removed from GAR, but left in iptables ipblock table;
#    GAR will still block the IP and add a duplicate entry to the ipblock config
#    file which will display in the GUI, but removing that entry or restarting/quiting
#    GAR will keep the manually added IP blocked
#
# 11/18/2007 - Stan Prescott (s-t-p)
#  - Ported the modified script done by Drew S. Dupont for SmoothWall 2.0 over to
#    SmoothWall 3.0
#
# 2/9/2008 - wkitty42
#  - added blocks count breakdown for manual or GAR and drop or reject

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );

use Socket;

my $modroot = "${swroot}/mods/GAR";
my (%cgiparams,%checked,%selected,%ipblocksettings);
my $ip_tracker_dir = "${modroot}/var/db";
my $filename = "${ip_tracker_dir}/GARipblock";
my $ipunblockfilename = "${ip_tracker_dir}/unblock";
my @vars;
my @current;
my $var, $addr;
my $needrestart = 0;
my $total_cnt = 0;
my $GAR_cnt = 0;
my $manual_cnt = 0;
my $drop_cnt = 0;
my $rej_cnt = 0;
my $log_cnt = 0;
my $active_cnt = 0;

&showhttpheaders();

$cgiparams{'OLDID'} = 0;
$cgiparams{'TARGET'} = 'DROP';
$cgiparams{'ACTIVE'} = 'off';
$cgiparams{'LOG'} = 'off';
$cgiparams{'AUTO'} = 'off';

$cgiparams{'COLUMN'} = 1;
$cgiparams{'ORDER'} = $tr{'log ascending'};

&getcgihash(\%cgiparams);

if ($ENV{'QUERY_STRING'} && ( not defined $cgiparams{'ACTION'} or $cgiparams{'ACTION'} eq "" ))
{
       my @temp = split(',',$ENV{'QUERY_STRING'});
       $cgiparams{'ORDER'}  = $temp[1] if ( defined $temp[1] and $temp[1] ne "" );
       $cgiparams{'COLUMN'} = $temp[0] if ( defined $temp[0] and $temp[0] ne "" );
}

my $errormessage = '';
my $updatebutton = 0;

if (($ENV{'QUERY_STRING'}) && ($cgiparams{'ACTION'} eq ''))
{
       @vars = split(/\&/, $ENV{'QUERY_STRING'});
       foreach $_ (@vars)
       {
               ($var, $addr) = split(/=/);
               if ($var eq 'ip')
               {
	               print "IP\n";
                       if (&validipormask($addr))
                       {
                               open (FILE,">>$filename") or die "1 - GARipblock.cgi unable to open $filename.";
                               flock FILE, 2;
                               print FILE "$addr,off,DROP,off,goofy-fu,off\n";
                               close (FILE);
                               $needrestart = 1;
                       }
               }
       }
       if ($needrestart) {
               my $success = message('setipblock');
               if (not defined $success) {
                       $errormessage = $tr{'smoothd failure'}; }
       }
}

if (($cgiparams{'ACTION'} eq $tr{'add'}) || ($cgiparams{'ACTION'} eq $tr{'update'}))
{
       unless(&validipormask($cgiparams{'SRC_IP'})) { $errormessage = $tr{'source ip bad'}; }
       open (FILE, $filename) or die "2 - GARipblock.cgi unable to open $filename.";
       @current = <FILE>;
       close (FILE);

       unless ($errormessage)
       {
	    ######################################
	    # Mod for new edit/update procedure
            ######################################
            if ($cgiparams{'ACTION'} eq $tr{'add'})
            {
                    open (FILE,">>$filename") or die "3 - GARipblock.cgi unable to open $filename.";
                    flock FILE, 2;
                    print FILE "$cgiparams{'SRC_IP'},$cgiparams{'LOG'},$cgiparams{'TARGET'},$cgiparams{'ACTIVE'},$cgiparams{'COMMENT'},$cgiparams{'AUTO'}\n";
                    close (FILE);
                    &log($tr{'ip block rule added'});
             } else {
                    open (FILE,">$filename") or die "4 - GARipblock.cgi unable to open $filename.";
                    flock FILE, 2;
                    $id = 0;
                    foreach $line (@current)
                    {
                         $id++;
                         if ($cgiparams{'OLDID'} eq $id)
                         {
                            print FILE "$cgiparams{'SRC_IP'},$cgiparams{'LOG'},$cgiparams{'TARGET'},$cgiparams{'ACTIVE'},$cgiparams{'COMMENT'},$cgiparams{'AUTO'}\n";
                         } else {
                            print FILE "$line";
                         }
                    }
                    close (FILE);
                    &log($tr{'ip block rule updated'});
               }
               undef %cgiparams;
               my $success = message('setipblock');

               if (not defined $success) {
                       $errormessage = $tr{'smoothd failure'}; }
       }
}

if (($cgiparams{'ACTION'} eq $tr{'remove'}) || ($cgiparams{'ACTION'} eq $tr{'edit'}) || ($cgiparams{'ACTION'} eq $tr{'switch to manual'}))
{
       open (FILE, "$filename") or die "5 - GARipblock.cgi unable to open $filename.";
       @current = <FILE>;
       close (FILE);

       my $count = 0;
       my $id = 0;
       my $line;
       my $removeorswitch = 0;
       my $source = 0;
       foreach $line (@current)
       {
               $id++;
               if ($cgiparams{$id} eq "on") {
                       $count++; }
       }
       if ($count ==  0) {
               $errormessage = $tr{'nothing selected'}; }
       if ($count > 1 && $cgiparams{'ACTION'} eq $tr{'edit'}) {
               $errormessage = $tr{'you can only select one item to edit'}; }
       unless ($errormessage)
       {
               open (FILE, ">$filename") or die "6 - GARipblock.cgi unable to open $filename.";
               flock FILE, 2;
	       # go ahead and open the GAR unblock file
		open (UNBLOCK, ">>$ipunblockfilename") or die "7 - GARipblock.cgi unable to open $ipunblockfilename.";
            	flock UNBLOCK, 2;
               $id = 0;
               foreach $line (@current) {
                       $id++;
                       unless ($cgiparams{$id} eq "on") {
                               print FILE "$line";
                       } elsif ($cgiparams{'ACTION'} eq $tr{'edit'}) {
                               chomp($line);
                               my @temp = split(/\,/,$line);
                               $cgiparams{'SRC_IP'} = $temp[0];
                               $cgiparams{'LOG'} = $temp[1];
                               $cgiparams{'TARGET'} = $temp[2];
                               $cgiparams{'ACTIVE'} = $temp[3];
                               $cgiparams{'COMMENT'} = $temp[4];
                               $cgiparams{'AUTO'} = $temp[5];
                               $cgiparams{'OLDID'} = $id;
                          $updatebutton = 1;
                          print FILE "$line\n";
                       } elsif ($cgiparams{'ACTION'} eq $tr{'switch to manual'}) {
                               chomp($line);
                               my @temp = split(/\,/,$line);
                               # If "GAR Added" flag is 'on', set it to off,
			       # change comment field, grab source,
                               # and set removeorswitch flag, else add line back to ipblock config
                               # and set error message
                               if ($temp[5] eq "on") {
			    	       $temp[4] = "converted from GAR maintained to Manual";
						   $temp[5] = "off";
                                       print FILE "$temp[0],$temp[1],$temp[2],$temp[3],$temp[4],$temp[5]\n";
                                       $source = $temp[0];
                                       $removeorswitch = 1;
                			# add IP to GAR's unblock list
                    			print UNBLOCK "$source\n";
                    			&log($tr{'ip block rule removed from GAR ipblock list'});
                               } else {
                                       print FILE "$line\n";
                                       $errormessage = $tr{'can not switch to manual'};
                               }
                       } else {
                               # Grab source and set removeorswitch flag
                               chomp($line);
                               my @temp = split(/\,/,$line);
                               $source = $temp[0];
                               $removeorswitch = 1;
            			# add IP to GAR's unblock list
            			print UNBLOCK "$source\n";
# we're not using the system's ipblock file or management tools so we now
# have to put the line back in the file for GAR to handle and we don't
# need to log that the line has been removed since it hasn't
#            			&log($tr{'ip block rule removed from GAR ipblock list'});
                        print FILE "$line\n";
                       }
               }
		close (UNBLOCK);
		close (FILE);

               if ($removeorswitch && (($cgiparams{'ACTION'} eq $tr{'remove'}) || ($cgiparams{'ACTION'} eq $tr{'switch to manual'}))) {
                       if ($cgiparams{'ACTION'} eq $tr{'remove'}) {
# we are not using the default ipblock file any more so we must rely on GAR
# to remove the iptables rules now instead of cheating and using the old 
# built-in setipblock routines that we used to be able to use.
#                               my $success = message('setipblock');
#                               if (not defined $success) {
#                                       $errormessage = $tr{'smoothd failure'}; }
#                               &log($tr{'ip block rule removed'});
                       }
               }
       }
}

if ($cgiparams{'ACTION'} eq $tr{'save'})
{
       $ipblocksettings{'RESOLVE'} = $cgiparams{'RESOLVE'};
#       &writehash("${swroot}/ipblock/settings", \%ipblocksettings);
       &writehash("${filename}", \%ipblocksettings);
}

if (-e "${swroot}/ipblock/settings") {
#       &readhash("${swroot}/ipblock/settings", \%ipblocksettings);
       &readhash("${filename}", \%ipblocksettings);
} else {
#       &writehash("${swroot}/ipblock/settings", \%ipblocksettings);
       &writehash("${filename}", \%ipblocksettings);
}

if ($cgiparams{'ACTION'} eq '')
{
       $cgiparams{'TARGET'} = 'DROP';
       $cgiparams{'ACTIVE'} = 'on';
}

$checked{'ACTIVE'}{'off'} = '';
$checked{'ACTIVE'}{'on'} = '';
$checked{'ACTIVE'}{$cgiparams{'ACTIVE'}} = 'CHECKED';

$checked{'LOG'}{'off'} = '';
$checked{'LOG'}{'on'} = '';
$checked{'LOG'}{$cgiparams{'LOG'}} = 'CHECKED';

$checked{'TARGET'}{'DROP'} = '';
$checked{'TARGET'}{'REJECT'} = '';
$checked{'TARGET'}{$cgiparams{'TARGET'}} = 'CHECKED';

## let's get the count of blocks with breakdown of manual or GAR
open (FILE, "$filename") or die "8 - GARipblock.cgi unable to open $filename.";
@current = <FILE>;
close (FILE);

foreach $line (@current)
{
    chomp($line);
    my @temp = split(/\,/,$line);
    $total_cnt++;
    # If "LOG" flag is 'on' increment log_cnt
    if ($temp[1] eq "on") {
	$log_cnt++;
    }
    # If "DROP" flag is 'on' increment drop_cnt otherwise increment rej_cnt
    if ($temp[2] eq "DROP") {
	$drop_cnt++;
    } else {
	$rej_cnt++;
    }
    # If "ACTIVE" flag is 'on' increment active_cnt
    if ($temp[3] eq "on") {
	$active_cnt++;
    }
    # If "GAR Added" flag is 'on' increment GAR_cnt otherwise increment manual_cnt
    if ($temp[5] eq "on") {
	$GAR_cnt++;
    } else {
	$manual_cnt++;
    }
}

####################################################
# text for add or edit box
####################################################
#if ($updatebutton) {
#       $buttontext = $tr{'update'};
#       $boxtext = $tr{'update current rule'};
#} else {
#       $buttontext = $tr{'add'};
#       $boxtext = $tr{'add a new rule'};
#}
##############################################

&openpage($tr{'gar ip block configuration'}, 1, '', 'networking');

&openbigbox('100%', 'LEFT');

&alertbox($errormessage);

&openbox($tr{'ip block stats'});
print qq{
<TABLE CLASS="list">
    <TR>
	<TH CLASS='list' STYLE='width: 14%;'>$tr{'total blocks'}</TH>
<!--	<TH CLASS='list' STYLE='width: 14%;'>$tr{'gar drop'}</TH> -->
<!--	<TH CLASS='list' STYLE='width: 14%;'>$tr{'gar reject'}</TH> -->
<!--	<TH CLASS='list' STYLE='width: 14%;'>$tr{'gar3'}</TH> -->
<!--	<TH CLASS='list' STYLE='width: 14%;'>$tr{'gar manual'}</TH> -->
	<TH CLASS='list' STYLE='width: 14%;'>$tr{'log'}</TH>
<!--	<TH CLASS='list' STYLE='width: 14%;'>$tr{'enabledtitle'}</TH> -->
    </TR>
    <TR CLASS='list'>
	<TD CLASS='list' STYLE='text-align: center;'>$total_cnt</TD>
<!--	<TD CLASS='list' STYLE='text-align: center;'>$drop_cnt</TD> -->
<!--	<TD CLASS='list' STYLE='text-align: center;'>$rej_cnt</TD> -->
<!--	<TD CLASS='list' STYLE='text-align: center;'>$GAR_cnt</TD> -->
<!--	<TD CLASS='list' STYLE='text-align: center;'>$manual_cnt</TD> -->
	<TD CLASS='list' STYLE='text-align: center;'>$log_cnt</TD>
<!--	<TD CLASS='list' STYLE='text-align: center;'>$active_cnt</TD> -->
    </TR>
</TABLE>
};
&closebox();

&openbox($tr{'current blocks'});

print "<FORM METHOD='POST'>\n";

my %render_settings = (
                       'url'     => "$tr{'garipblock'}.cgi?[%COL%],[%ORD%]",
                       'columns' => [
                               {
                                       column => '1',
                                       title  => "$tr{'source ip'}",
                                       size   => 30,
                                       sort   => \&ipcompare,
                                       tr     => {
                                               '0.0.0.0/0' => 'N/A',
                                       },
                               },
                               {
                                       column => '3',
                                       title  => "$tr{'action'}",
                                       size   => 20,
				       sort   => 'cmp',
                                       tr     => {
                                               'REJECT' => 'REJECT',
                                               'DROP'   => 'DROP',
                                               'RETURN' => 'EXCEPTION',
                                       },
                               },
#                               {
#                                       column => '6',
#                                       title  => "$tr{'gar added'}",
#                                       size   => 15,
#				       sort   => 'cmp',
#                                       tr     => 'onoff',
#                                       align  => 'center',
#                               },
#                               {
#                                       column => '2',
#                                       title => "$tr{'log'}",
#                                       size   => 20,
#				       sort   => 'cmp',
#                                       tr     => 'onoff',
#                                       align  => 'center',
#                               },
#                               {
#                                       column => '4',
#                                       title  => "$tr{'enabledtitle'}",
#                                       size   => 15,
#				       sort   => 'cmp',
#                                       tr     => 'onoff',
#                                       align  => 'center',
#                               },
                               {
                                       title  => "$tr{'mark'}",
                                       size   => 15,
                                       mark   => ' ',
                               },
                               {
                                       column => '5',
                                       title => "$tr{'comment'}",
                                       break => 'line',
                               }
                       ]
                       );

print <<END;
<script type=\"text/javascript\">
<!--
function displayGAR_Tracker(url) {
        window.open("/cgi-bin/mods/GAR/gartracker.cgi?track="+url,"disposableHelpWindow","resizable=yes,status=no,scrollbars=yes,width=650,height=500");
}

function GARviewPort() {
    var h = window.innerHeight || document.documentElement.clientHeight || document.getElementsByTagName('body')[0].clientHeight;
    var w = window.innerWidth || document.documentElement.clientWidth || document.getElementsByTagName('body')[0].clientWidth;
    return { width : w , height : h }
}

var page_height;
var blocklist_height;

page_height = GARviewPort().height;
//blocklist_height = parseInt(page_height - 542);
blocklist_height = parseInt(page_height - 400);

document.write("<!-- " + page_height + " : " + blocklist_height + " //-->");
if (page_height <= 733)
{
    document.write("<div>");
} else {
    document.write("<div style='height: " + blocklist_height + "px; width: 100%; overflow: auto;'>");
}
//-->
</script>
END
&displaytable( $filename, \%render_settings, $cgiparams{'ORDER'}, $cgiparams{'COLUMN'} );
#print "</div>";

print <<END
<TABLE WIDTH='100%'>
<TR>
<TD WIDTH='33%' ALIGN='CENTER'><INPUT TYPE='SUBMIT' NAME='ACTION' VALUE='$tr{'remove'}'></TD>
<TD WIDTH='34%' ALIGN='CENTER'><INPUT TYPE='SUBMIT' NAME='ACTION' VALUE='$tr{'switch to manual'}'></TD>
<!-- <TD WIDTH='33%' ALIGN='CENTER'><INPUT TYPE='SUBMIT' NAME='ACTION' VALUE='$tr{'edit'}'></TD> -->
</TR>
</TABLE>
END
;

print "</FORM>\n";

&alertbox('add', 'add');

&closebox();

&closebigbox();

&closepage($errormessage);
