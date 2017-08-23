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
#
# 15 Jan 2015 - wkitty42
#  - huge rewrite for the limited capabilities needed for GAR v3+

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );

use Socket;

my ${GAR_Root_dir} = "/mods/GAR";
my ${GAR_Home_dir} = "${swroot}"."${GAR_Root_dir}";
my ${GAR_Logo} = "${GAR_Root_dir}/ui/img/alligator-gar-50-2.png";
my (%SWEprodvals,%cgiparams,%checked,%selected,%ipblocksettings);
my ${ip_tracker_dir} = "${GAR_Home_dir}/var/db";
my ${GARipblock_filename} = "${ip_tracker_dir}/GARipblock";
my ${SWEipblock_filename} = "${swroot}/ipblock/config";
my ${GARipunblock_filename} = "${ip_tracker_dir}/unblock";
my ${GAR_Script_file} = "$GAR_Home_dir/usr/bin/GAR";
my @vars;
my @current;
my ${var}, ${addr};
my ${need_sysIPRestart} = 0;
my ${total_cnt} = 0;
my ${GAR_cnt} = 0;
my ${manual_cnt} = 0;
my ${drop_cnt} = 0;
my ${reject_cnt} = 0;
my ${forced_logging_cnt} = 0;
my ${active_cnt} = 0;
&readhash("${swroot}/main/productdata",\%SWEprodvals);

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
       $cgiparams{'ORDER'}  = ${temp[1]} if ( defined ${temp[1]} and ${temp[1]} ne "" );
       $cgiparams{'COLUMN'} = ${temp[0]} if ( defined ${temp[0]} and ${temp[0]} ne "" );
}

my ${errormessage} = '';
my ${update_button} = 0;


if ($cgiparams{'ACTION'} eq $tr{'remove'}) {
  # open the ipblock file for reading and writing... lock it and keep it open for the duration of this routine
  open (GARIPBLOCKFILE, "+<${GARipblock_filename}") or die "1 - GARipblock.cgi unable to open ${GARipblock_filename}.";
  flock GARIPBLOCKFILE, 2;
  @current = <GARIPBLOCKFILE>;
  #close (GARIPBLOCKFILE);
  truncate (GARIPBLOCKFILE, 0) or die "2 - GARipblock.cgi unable to truncate ${GARipblock_filename}.";
  seek (GARIPBLOCKFILE, 0, 0);

  my ${count} = 0;
  my ${id} = 0;
  my ${line};
  my ${source} = 0;
  foreach ${line} (@current) {
    ${id}++;
    if ($cgiparams{${id}} eq "on") {
      ${count}++;
    }
  }
  if (${count} == 0) {
    ${errormessage} = $tr{'nothing selected'};
  }
  unless (${errormessage}) {
    #open (GARIPBLOCKFILE, ">${GARipblock_filename}") or die "2 - GARipblock.cgi unable to open ${GARipblock_filename}.";
    #flock GARIPBLOCKFILE, 2;
    # go ahead and open the GAR unblock file
    open (GARUNBLOCKFILE, ">>${GARipunblock_filename}") or die "3 - GARipblock.cgi unable to open ${GARipunblock_filename}.";
    flock GARUNBLOCKFILE, 2;
    ${id} = 0;
    foreach ${line} (@current) {
      ${id}++;
      unless ($cgiparams{${id}} eq "on") {
        print GARIPBLOCKFILE "${line}";
      } else {
        chomp(${line});
        # split the fields
        my @temp = split(/\,/,${line});
        # add IP (first field) to GAR's unblock list
        print GARUNBLOCKFILE "${temp[0]}\n";
        # add IP back to the blockfile for GAR to remove
        print GARIPBLOCKFILE "${line}\n";
      }
    }
    # close the ipblock file first
    #close (GARIPBLOCKFILE);
    # then close the unblock and let GAR have access to it
    close (GARUNBLOCKFILE);
  }
  # now we close the ipblock file at the end of the routine
  close (GARIPBLOCKFILE);
}

if ($cgiparams{'ACTION'} eq $tr{'switch to manual'}) {
  # open the ipblock file for reading and writing... lock it and keep it open for the duration of this routine
  open (GARIPBLOCKFILE, "+<${GARipblock_filename}") or die "4 - GARipblock.cgi unable to open ${GARipblock_filename}.";
  flock GARIPBLOCKFILE, 2;
  @current = <GARIPBLOCKFILE>;
  #close (GARIPBLOCKFILE);
  truncate (GARIPBLOCKFILE, 0) or die "5 - GARipblock.cgi unable to truncate ${GARipblock_filename}.";
  seek (GARIPBLOCKFILE, 0, 0);

  my ${count} = 0;
  my ${id} = 0;
  my ${line};
  my ${source} = 0;
  foreach ${line} (@current) {
    ${id}++;
    if ($cgiparams{${id}} eq "on") {
      ${count}++;
    }
  }
  if (${count} ==  0) {
    ${errormessage} = $tr{'nothing selected'};
  }
  unless (${errormessage}) {
    # open GAR's ipblock file
    #open (GARIPBLOCKFILE, ">${GARipblock_filename}") or die "5 - GARipblock.cgi unable to open ${GARipblock_filename}.";
    #flock GARIPBLOCKFILE, 2;
    # open the system's ipblock file
    open (SWEIPBLOCKFILE, ">>${SWEipblock_filename}") or die "6 - GARipblock.cgi unable to open ${SWEipblock_filename}.";
    flock SWEIPBLOCKFILE, 2;
    # open GAR's unblock file
    open (GARUNBLOCKFILE, ">>${GARipunblock_filename}") or die "7 - GARipblock.cgi unable to open ${GARipunblock_filename}.";
    flock GARUNBLOCKFILE, 2;
    ${id} = 0;
    foreach ${line} (@current) {
      ${id}++;
      unless ($cgiparams{${id}} eq "on") {
        print GARIPBLOCKFILE "${line}";
      } else {
        chomp(${line});
        # first make sure the unmodified line goes back into GAR's
        # ipblock list so that GAR can remove it when it reads the
        # unblock file
        print GARIPBLOCKFILE "${line}\n";
        # now split the line into the individual fields
        my @temp = split(/\,/,${line});
        # add the IP (first field) to GAR's unblock file
        print GARUNBLOCKFILE "${temp[0]}\n";
        # finally change the comment field to indicate the IP was
        # moved from the GAR ipblock to the system's ipblock and
        # write only the needed ipblock fields (0-4) to the system's
        # ipblock file
        ${temp[4]} = "Switched from GAR maintained to Manual";
        print SWEIPBLOCKFILE "${temp[0]},${temp[1]},${temp[2]},${temp[3]},${temp[4]}\n";
        # now indicate that we need to restart the system's ipblock
        ${need_sysIPRestart} = 1;
      }
    }
    #close (GARIPBLOCKFILE);
    close (GARUNBLOCKFILE);
    close (SWEIPBLOCKFILE);
    if (${need_sysIPRestart}) {
      my ${success} = message('setipblock');
      if (not defined ${success}) {
        ${errormessage} = $tr{'smoothd failure'};
      }
    }
  }
  # now close the ipblock file at the end of this routine
  close (GARIPBLOCKFILE);
}

if ($cgiparams{'ACTION'} eq '') {
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

# let's get the count of blocks with breakdown of manual or GAR
open (GARIPBLOCKFILE, "${GARipblock_filename}") or die "8 - GARipblock.cgi unable to open ${GARipblock_filename}.";
@current = <GARIPBLOCKFILE>;
close (GARIPBLOCKFILE);

foreach ${line} (@current)
{
    chomp(${line});
    my @temp = split(/\,/,${line});
    ${total_cnt}++;
    # If "LOG" flag is 'on' increment log_cnt
    if (${temp[1]} eq "on") {
	${forced_logging_cnt}++;
    }
    # If "DROP" flag is 'on' increment drop_cnt otherwise increment rej_cnt
    if (${temp[2]} eq "DROP") {
	${drop_cnt}++;
    } else {
	${reject_cnt}++;
    }
    # If "ACTIVE" flag is 'on' increment active_cnt
    if (${temp[3]} eq "on") {
	${active_cnt}++;
    }
    # If "GAR Added" flag is 'on' increment GAR_cnt otherwise increment manual_cnt
    if (${temp[5]} eq "on") {
	${GAR_cnt}++;
    } else {
	${manual_cnt}++;
    }
}

&openpage($tr{'gar ip block configuration'}, 1, '', 'networking');

&openbigbox('100%', 'LEFT');

&alertbox(${errormessage});

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
	<TD CLASS='list' STYLE='text-align: center;'>${total_cnt}</TD>
<!--	<TD CLASS='list' STYLE='text-align: center;'>${drop_cnt}</TD> -->
<!--	<TD CLASS='list' STYLE='text-align: center;'>${reject_cnt}</TD> -->
<!--	<TD CLASS='list' STYLE='text-align: center;'>${GAR_cnt}</TD> -->
<!--	<TD CLASS='list' STYLE='text-align: center;'>${manual_cnt}</TD> -->
	<TD CLASS='list' STYLE='text-align: center;'>${forced_logging_cnt}</TD>
<!--	<TD CLASS='list' STYLE='text-align: center;'>${active_cnt}</TD> -->
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
var blocklist_height;

page_height = GARviewPort().height;
//blocklist_height = parseInt(page_height - 378);
blocklist_height = parseInt(page_height - 400);
if (page_height >= 525) {
    document.write("<div style='height: " + blocklist_height + "px; width: 100%; overflow: auto;'>");
} else {
    document.write("<div>");
}
//-->
</script>
END
;

&displaytable( ${GARipblock_filename}, \%render_settings, $cgiparams{'ORDER'}, $cgiparams{'COLUMN'} );

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
<TD WIDTH='33%' ALIGN='CENTER'><INPUT TYPE='SUBMIT' NAME='ACTION' VALUE='$tr{'remove'}'></TD>
<TD WIDTH='33%' ALIGN='CENTER'><script type=\"text/javascript\">document.write("PGH:" + page_height + " BLH:" + blocklist_height + "<br/>");</script></TD>
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


&closepage(${errormessage});
