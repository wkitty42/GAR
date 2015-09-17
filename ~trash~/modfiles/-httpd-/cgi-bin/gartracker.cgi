#!/usr/bin/perl
#
# SmoothWall CGIs
#
# This code is distributed under the terms of the GPL
#
# (c) The SmoothWall Team

use lib "/usr/lib/smoothwall";
use header qw( :standard );

use Socket;
use POSIX;
use Time::Local;

@months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

sub indexArray($@)
{
    my ${s} = shift;
    $_ eq ${s} && return @_ while $_ = pop;
    -1;
}

if ($ENV{'QUERY_STRING'}) {
    $_ = $ENV{'QUERY_STRING'};
    my ${action};
    $_ =~ s/\+/ /g;
    my @temp = split(/\&/);
    foreach $_ (@temp) {
	(${var}, ${val}) = split(/\=/);
	if (${var} eq 'track') { 
	    ${tracker_ip} = ${val};
	} else {
	    die "bad query string";
	}
    }
}

my ${tracker_file} = "${swroot}/guardian/${tracker_ip}";
my ${hostname};

if (-e ${tracker_file}) {
    open (FILE, "${tracker_file}");
    @current = <FILE>;
    close (FILE);

    ${hostname} = gethostbyaddr(inet_aton(${tracker_ip}), AF_INET);
    if (!${hostname}) { ${hostname} = $tr{'lookup failed'}; }
    ${count} = @current;
    ${now_time} = time;
    (${nsec}, ${nmin}, ${nhr}, ${nday}, ${nmon}, ${nyr}) = localtime(${now_time});
    if (length(${nsec}) == 1) {${nsec} = "0".${nsec};}
    if (length(${nmin}) == 1) {${nmin} = "0".${nmin};}
    if (length(${nhr})  == 1) {${nhr}  = "0".${nhr};}
    if (length(${nday}) == 1) {${nday} = "0".${nday};}
#    ${nmon} += 1;
    ${nyr} += 1900;
    ${now_string} = ${nday}."-".@months[${nmon}]."-".${nyr}." ".${nhr}.":".${nmin}.":".${nsec};
    

    # get and calculate time since starting block
    (${first_active}, ${tr1}, ${tr2}) = split(' \*\* ',$current[0]);
    (${tr1}, ${first_date}, ${first_time}) = split(/\s+/, ${first_active});
    (${first_day}, ${first_month}, ${first_year}) = split(/\-/,${first_date});
    (${first_hour}, ${first_minute}, ${first_second}) = split(/:/,${first_time});
    if (length(${first_day}) == 1) {${first_date} = "0".${first_day}."-".${first_month}."-".${first_year};}
    ${first_month_num} = indexArray(${first_month},@months);
    ${start_time} = timelocal(${first_second}, ${first_minute}, ${first_hour}, ${first_day}, ${first_month_num}, ${first_year} - 1900,0,0);
    ${intime} = (${now_time} - ${start_time});
    if (${intime} >= 0) {
	${strt_secs} = ${intime} % 60;
	${intime} = (${intime} - ${strt_secs}) / 60;
	${strt_mins} = ${intime} % 60;
	${intime} = (${intime} - ${strt_mins}) / 60;
	${strt_hours} = ${intime} % 24;
	${intime} = (${intime} - ${strt_hours}) / 24;
	${strt_days} = ${intime};
#	${strt_days} = ${intime} % 7;
#	${strt_weeks} = (${intime} - ${strt_days}) / 7;

	${strt_str} = ${strt_secs} . "s";
	if (${strt_mins} gt 0) { ${strt_str} = ${strt_mins} . "m " . ${strt_secs} . "s"; }
	if (${strt_hours} gt 0) { ${strt_str} = ${strt_hours} . "h " . ${strt_mins} . "m " . ${strt_secs} . "s"; }
	if (${strt_days} gt 0) { ${strt_str} = ${strt_days} . "d " . ${strt_hours} . "h " . ${strt_mins} . "m " . ${strt_secs} . "s"; }
#	if (${strt_weeks} gt 0) { ${strt_str} = ${strt_weeks} . "w " . ${strt_days} . "d " . ${strt_hours} . "h " . ${strt_mins} . "m " . ${strt_secs} . "s"; }
    } else {
	${intime} = (${start_time} - ${now_time});
	${strt_secs} = ${intime} % 60;
	${intime} = (${intime} - ${strt_secs}) / 60;
	${strt_mins} = ${intime} % 60;
	${intime} = (${intime} - ${strt_mins}) / 60;
	${strt_hours} = ${intime} % 24;
	${intime} = (${intime} - ${strt_hours}) / 24;
	${strt_days} = ${intime};
#	${strt_days} = ${intime} % 7;
#	${strt_weeks} = (${intime} - ${strt_days}) / 7;

	${strt_str} = ${strt_secs} . "s";
	if (${strt_mins} gt 0) { ${strt_str} = ${strt_mins} . "m " . ${strt_secs} . "s"; }
	if (${strt_hours} gt 0) { ${strt_str} = ${strt_hours} . "h " . ${strt_mins} . "m " . ${strt_secs} . "s"; }
	if (${strt_days} gt 0) { ${strt_str} = ${strt_days} . "d " . ${strt_hours} . "h " . ${strt_mins} . "m " . ${strt_secs} . "s"; }
#	if (${strt_weeks} gt 0) { ${strt_str} = ${strt_weeks} . "w " . ${strt_days} . "d " . ${strt_hours} . "h " . ${strt_mins} . "m " . ${strt_secs} . "s"; }
	${strt_str} = "Starts ".${strt_str}." in the future!";
    }
    ${strt_str} = "(".${strt_str}." ago)";

    # get and calculate time remaining for block
    (${tr1}, ${last_expire}, ${tr2}) = split(' \*\* ',$current[$count-1]);
    if (${count} le 1) {
	(${tr1}, ${go_date}, ${go_time}) = split(/\s+/, ${last_expire});
    } else {
	(${tr1}, ${tr2}, ${go_date}, ${go_time}) = split(/\s+/, ${last_expire});
    }
    (${go_day}, ${go_month}, ${go_year}) = split(/\-/,${go_date});
    (${go_hour}, ${go_minute}, ${go_second}) = split(/:/,${go_time});
    if (length(${go_day}) == 1) {${go_date} = "0".${go_day}."-".${go_month}."-".${go_year};}
    ${go_month_num} = indexArray(${go_month},@months);
    ${expire_time} = timelocal(${go_second}, ${go_minute}, ${go_hour}, ${go_day}, ${go_month_num}, ${go_year} - 1900,0,0);
    ${remaintime} = (${expire_time} - ${now_time});
    if (${remaintime} >= 0) {
	${rt_secs} = ${remaintime} % 60;
	${remaintime} = (${remaintime} - ${rt_secs}) / 60;
	${rt_mins} = ${remaintime} % 60;
	${remaintime} = (${remaintime} - ${rt_mins}) / 60;
	${rt_hours} = ${remaintime} % 24;
	${remaintime} = (${remaintime} - ${rt_hours}) / 24;
	${rt_days} = ${remaintime};
#	${rt_days} = ${remaintime} % 7;
#	${rt_weeks} = (${remaintime} - ${rt_days}) / 7;

	${go_str} = ${rt_secs} . "s";
	if (${rt_mins} gt 0) { ${go_str} = ${rt_mins} . "m " . ${rt_secs} . "s"; }
	if (${rt_hours} gt 0) { ${go_str} = ${rt_hours} . "h " . ${rt_mins} . "m " . ${rt_secs} . "s"; }
	if (${rt_days} gt 0) { ${go_str} = ${rt_days} . "d " . ${rt_hours} . "h " . ${rt_mins} . "m " . ${rt_secs} . "s"; }
#	if (${rt_weeks} gt 0) { ${go_str} = ${rt_weeks} . "w " . ${rt_days} . "d " . ${rt_hours} . "h " . ${rt_mins} . "m " . ${rt_secs} . "s"; }
    } else {
	${remaintime} = (${now_time} - ${expire_time});
	${rt_secs} = ${remaintime} % 60;
	${remaintime} = (${remaintime} - ${rt_secs}) / 60;
	${rt_mins} = ${remaintime} % 60;
	${remaintime} = (${remaintime} - ${rt_mins}) / 60;
	${rt_hours} = ${remaintime} % 24;
	${remaintime} = (${remaintime} - ${rt_hours}) / 24;
	${rt_days} = ${remaintime};
#	${rt_days} = ${remaintime} % 7;
#	${rt_weeks} = (${remaintime} - ${rt_days}) / 7;

	${go_str} = ${rt_secs} . "s";
	if (${rt_mins} gt 0) { ${go_str} = ${rt_mins} . "m " . ${rt_secs} . "s"; }
	if (${rt_hours} gt 0) { ${go_str} = ${rt_hours} . "h " . ${rt_mins} . "m " . ${rt_secs} . "s"; }
	if (${rt_days} gt 0) { ${go_str} = ${rt_days} . "d " . ${rt_hours} . "h " . ${rt_mins} . "m " . ${rt_secs} . "s"; }
#	if (${rt_weeks} gt 0) { ${go_str} = ${rt_weeks} . "w " . ${rt_days} . "d " . ${rt_hours} . "h " . ${rt_mins} . "m " . ${rt_secs} . "s"; }
	${go_str} = "Expired ".${go_str}." ago!";
    }
    ${go_str} = "(".${go_str}." left)";
}

&showhttpheaders();

&openpage($tr{'gartracker title'}." - ${tracker_ip}", 1, '', 'help');

&openbigbox();

print <<END;
    <table class='box' border='0'>
	<tr>
	    <td colspan='2' class='helpheader'>
		<a href="javascript:window.close();"><img src="/ui/img/help.footer.png" alt="click to close window"></a>
	    </td>
	</tr>
END

if (-e ${tracker_file}) {
    print <<END;
	<tr>
	    <td width='50%' style='text-align: center; font-weight: bold; font-size: 12px;'>
		$tr{'gartracker ip'} ${tracker_ip}
	    </td>
	    <td width='50%' style='text-align: center; font-weight: bold; font-size: 12px;'>
		$tr{'gartracker host'} ${hostname}
	    </td>
	</tr>
	<tr>
	    <td width='50%' style='text-align: center; font-weight: bold; font-size: 12px;'>
		$tr{'gartracker alert count'} ${count}
	    </td>
	    <td width='50%' style='text-align: center; font-weight: bold; font-size: 12px;'>
		$tr{'gartracker current time'} ${now_string}
	    </td>
	</tr>
	<tr>
	    <td colspan='2' style='text-align: center; font-weight: bold; font-size: 12px;'>
		$tr{'gartracker block started'} ${first_date} ${first_time} ${strt_str}
	    </td>
	</tr>
	<tr>
	    <td colspan='2' style='text-align: center; font-weight: bold; font-size: 12px;'>
		$tr{'gartracker block expires'} ${go_date} ${go_time} ${go_str}
	    </td>
	</tr>
	<tr>
	    <td colspan='2' style='text-align: justify; font-size: 11px;'>
		<table class='list' cellpadding='4'>
		    <tr>
			<th class='list' style='width: 20%'>$tr{'gartracker activity date'}</th>
			<th class='list' style='width: 20%'>$tr{'gartracker expire date'}</th>
			<th class='list' style='width: 60%'>$tr{'gartracker rule violation'}</th>
		    </tr>
END
    foreach my ${line} (@current){
	chomp ${line};
        my (${record}, ${expire}, ${rule}) = split(' \*\* ',${line});
        ${record} =~ /(.*): (.*)/;
        ${record} = $2;
        ${expire} =~ /(.*): (.*)/;
        ${expire} = $2;
    
    print <<END;
			<tr class='list'>
			    <td class='list' style='text-align: left; vertical-align: top; white-space: nowrap;'>${record}</td>
			    <td class='list' style='text-align: left; vertical-align: top; white-space: nowrap;'>${expire}</td>
			    <td class='list' style='text-align: left;'>${rule}</td>
			</tr>
END
    }
    print <<END;
			<tr class='list'>
			    <th class='list' style='text-align: left;'>&nbsp;</th>
			    <th class='list' style='text-align: left;'>&nbsp;</th>
			    <th class='list' style='text-align: left;'>&nbsp;</th>
			</tr>
		</table>
	    </td>
	</tr>
	<tr>
	    <td colspan='2'>
END
    &openbox("WHOIS $tracker_ip");
    print "<div style='height: 150px; width: 100%; overflow: auto;'>\n";
    print "<pre style='font-size: 10px;'>\n";
    system('/usr/bin/whois', '--nocgi', ${tracker_ip});
    print "</pre>\n";
    print "</div>\n";
    &closebox();
    print <<END;
	    </td>
	</tr>
END
} else {
    print <<END;
	<tr>
	    <td style='text-align: justify; font-size: 11px;'>
		<table class='list' cellpadding='4'>
		    <tr>
			<td colspan='3'>&nbsp;</td>
		    </tr>
		    <tr>
			<td style='width: 10%; text-align: left;'>&nbsp;</td>
			<td style='width: 80%; text-align: center; white-space: nowrap; font-weight: bold; font-size: 15px;'>
			    $tr{'tracking file for'} ${tracker_ip} $tr{'not found'}
			    <br/><br/>
			</td>
			<td style='width: 10%; text-align: left;'>&nbsp;</td>
		    </tr>
		    <tr>
			<td style='width: 10%; text-align: left;'>&nbsp;</td>
			<td style='width: 80%; text-align: center; white-space: nowrap; font-weight: normal; font-size: 12px;'>
			    $tr{'did it expire'}
			</td>
			<td style='width: 10%; text-align: left;'>&nbsp;</td>
		    </tr>
		    <tr>
			<td colspan='3'>&nbsp;</td>
		    </tr>
		</table>
	    </td>
	</tr>
END
}
print <<END;
	<tr>
	    <td colspan='2' class='helpfooter'>
		<a href="javascript:window.close();"><img src="/ui/img/help.footer.png" alt="click to close window"></a>
	    </td>
	</tr>
    </table>
END

&closebigbox();

&closepage('blank');
