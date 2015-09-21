#!/usr/bin/perl
#
# This code is distributed under the terms of the GPL
#
# (c) Tiago Freitas Leal
#
# install script for Guardain-Reactive Firewall

use lib "/usr/lib/smoothwall";
use header qw(:standard);
use smoothd qw( message );
use Config::Patch;

my $vererr = 0;
if (!(-e "/usr/lib/smoothwall/langs/base.pl")) {
	$vererr++;
	goto EXIT;
}

my %netsettings;

&readhash("${swroot}/ethernet/settings", \%netsettings);

if (-e "/usr/lib/smoothd/sysguardian.so") {
	my $success = message('guardianstop');

	unless (defined $success) {
		print "smoothd failure"; }
}

if (-e "/var/smoothwall/guardian/saved") {
	unlink "/var/smoothwall/guardian/saved";
}

# # # # # # # # # # # #
# handle file copying #
# # # # # # # # # # # #

my $mod = '/var/smoothwall/mods/GAR/modfiles';
my $bkp = '/var/smoothwall/mods/GAR/backup';

$dir = '/httpd/cgi-bin';
unless (-e "/var/smoothwall/mods/GAR/backup/ids.cgi") {
	&backup ('ids.cgi', $dir, $bkp);
	&backup ('ipblock.cgi', $dir, $bkp);

	$dir = '/httpd/html/help';
	&backup ('ids.cgi.html.en', $dir, $bkp);
}

$dir = '/httpd/html/ui/js';
&backup ('script.js', $dir, $bkp);
&install ('script.js', $dir, $mod);

$dir = '/httpd/cgi-bin';
&install ('ids.cgi', $dir, $mod);
&install ('ipblock.cgi', $dir, $mod);
&install ('gar-tracker.cgi', $dir, $mod);

$dir = '/httpd/cgi-bin/logs.cgi';
&install ('guardian.dat', $dir, $mod);

$dir = '/httpd/html/help';
&install ('ids.cgi.html.en', $dir, $mod);

$dir = '/usr/lib/smoothd';
&install ('sysguardian.so', $dir, $mod);

$dir = '/usr/lib/smoothwall/menu/5000_Logs';
&install ('3001_guardian.list', $dir, $mod);

unless (-e "/usr/lib/smoothwall/services/guardian") {
	$dir = '/usr/lib/smoothwall/services';
	&install ('guardian', $dir, $mod);
}

if (-e "/etc/guardian.conf") { system("/bin/mv /etc/guardian.conf /var/smoothwall/mods/GAR/backup"); }
$dir = '/etc';
&install ('guardian.conf', $dir, $mod);

if (-e "/usr/local/sbin/guardian.pl") { unlink "/usr/local/sbin/guardian.pl"; }
$dir = '/usr/local/sbin';
&install ('guardian.pl', $dir, $mod);

system("/bin/touch", '/var/smoothwall/mods/GAR/config');
system("/bin/chown nobody:nobody /var/smoothwall/mods/GAR/config");

# # # # # # # # # # # #
# handle file editing #
# # # # # # # # # # # #

if (-e "/etc/cron.weekly/update-snortrules") {
	open(FILE, ">>/var/smoothwall/snort/settings") or die 'Unable to open snort settings file';
	print FILE "AUTOUPD=on\n";
	close FILE;
}

my $statuscgi = "/httpd/cgi-bin/status.cgi";
my $sysinit = "/etc/rc.d/rc.sysinit";
my $updatered = "/etc/rc.d/rc.updatered";
my $guardconf = "/etc/guardian.conf";

my $patcher = Config::Patch->new(
        file => $sysinit,
        key  => "gar",
        );
$patcher->remove();
$patcher->insert(qr(Silencing kernel)sm,
"if [ -e \"\/etc\/guardian.conf\" ]; then
	echo \"Starting Guardian (if enabled)\"
	\/usr\/bin\/smoothcom guardianrestart
fi
");

$patcher = Config::Patch->new(
        file => $statuscgi,
        key  => "gar",
        );
$patcher->remove();
$patcher->replace(qr(my \$servicename)sm,
"	my \$servicename;
	if (\$file eq \'guardian\') \{
		\$servicename = \'guardian\.pl\';
	\} else \{
		\$servicename = \$file;
	}
");

$patcher = Config::Patch->new(
        file => $updatered,
        key  => "gar",
        );
$patcher->remove();

open (FILE, "</var/smoothwall/red/iface") or die 'Unable to open red iface file';
my $redif = <FILE>;
close FILE;
		
$patcher = Config::Patch->new(
        file => $guardconf,
        key  => "gar",
        );
$patcher->remove();
$patcher->replace(qr(Interface)sm,
"Interface	$redif");

my ($line, @splitline);
chomp $redif;
if ($redif eq "ppp0") {
	open (FILE, "$guardconf") or die 'Unable to open guardian.conf';
	my @temp = <FILE>;
	close FILE;

	open (FILE, ">$guardconf") or die 'Unable to open guardian.conf';
	foreach $line (@temp) {
		chomp $line;
		@splitline = split (/\t+/, $line);
		unless ($splitline[0] eq "HostGatewayByte") {
			print FILE "$line\n";
		} else {
			print FILE "\#$line\n";
		}
	}
	close FILE;
}

open (FILE, "</var/smoothwall/red/dns1") or die 'Unable to open dns file';
my $dns1 = <FILE>;
close FILE;
chomp $dns1;

open (FILE, "</var/smoothwall/red/dns2") or die 'Unable to open dns file';
my $dns2 = <FILE>;
close FILE;
chomp $dns2;

unless (-e "/etc/guardian.ignore") {
	system("/bin/touch /etc/guardian.ignore");
	system("/bin/chown nobody:nobody /etc/guardian.ignore");
	open (FILE, ">>/etc/guardian.ignore") or die 'Unable to open guardian ignore file';
	print FILE "$netsettings{'GREEN_ADDRESS'}\n";
	if ($netsettings{'ORANGE_DEV'}) { print FILE "$netsettings{'ORANGE_ADDRESS'}\n"; }
	if ($netsettings{'PURPLE_DEV'}) { print FILE "$netsettings{'PURPLE_ADDRESS'}\n"; }
	print FILE "$dns1\n";
	if ($dns2) { print FILE "$dns2\n" }
	close FILE;
}

unless (-e "/etc/guardian.target") {
	system("/bin/touch", '/etc/guardian.target');
	system("/bin/chown nobody:nobody /etc/guardian.target");
}

unless (-e "/var/smoothwall/guardian/unblock") { 
	system("/bin/mkdir /var/smoothwall/guardian/");
	system("/bin/chown nobody:nobody /var/smoothwall/guardian/");
	system("/bin/touch /var/smoothwall/guardian/unblock");
	system("/bin/chown nobody:nobody /var/smoothwall/guardian/unblock");
}

unless (-e "/var/smoothwall/guardian/saved") { 
	system("/bin/touch", '/var/smoothwall/guardian/saved');
	system("/bin/chown nobody:nobody /var/smoothwall/guardian/saved"); 
}

print "Setting permissions...\n";
system("/bin/chown nobody:nobody /etc/guardian.conf");

print "Creating guardian log directories if they do not exist...\n";
unless (-e "/var/log/guardian/guardian.log") {
	system("/bin/mkdir /var/log/guardian/");
	system("/bin/mkdir /var/log/guardian/old/");
	system("/bin/touch /var/log/guardian/guardian.log");
	system("/bin/touch /var/log/guardian/guard.log");
	system("/bin/touch /var/log/guardian/guard.err");
	system("/bin/chown nobody:nobody /var/log/guardian/");
	system("/bin/chown nobody:nobody /var/log/guardian/old");
	system("/bin/chown nobody:nobody /var/log/guardian/*");
}

unless (-e "/var/log/guardian/old/") {
	system("/bin/mkdir /var/log/guardian/old/");
	system("/bin/chown nobody:nobody /var/log/guardian/old/");
}

unless (-e "/var/smoothwall/snort/rules/sid-msg.map") { system("/bin/touch", '/var/smoothwall/snort/rules/sid-msg.map'); }

system("/bin/chown nobody:nobody /var/smoothwall/snort/rules/*");

open (FILE,  "+>/var/smoothwall/mods/GAR/installed") or die 'Unable to create installed file';
print FILE "GAR-3.0-SWE3\n";
close FILE;

print "Restarting smoothd...";
system("/bin/kill -9 smoothd && smoothd");
sleep (2);
system("/usr/sbin smoothd");

EXIT:

if ($vererr > 0) {
	print "You are not running SmoothWall Express version 3.0\n \n";
	print "This version of the Guardian Active Response mod requires SWE 3.0\n \n";
	print "Terminating GAR mod installation.\n";
}

# # # #
# end #
# # # #

#
# This code is distributed under the terms of the GPL
#
# (c) Tiago Freitas Leal

$version = '2.1';

#	$storebkp =	where to store backup of the files that are changed by your mod
#	$moddir =	where your mod files are
#	$wkdir =	where you are changing files (backup from and copy to)
#
#	backupinstall ($file ,$wkdir ,$storebkp ,$moddir);
#	backup ($file ,$wkdir ,$storebkp);
#	install ($file ,$wkdir ,$moddir);
#	uninstallrestore ($file ,$wkdir ,$storebkp);
#	uninstall ($file  ,$wkdir);
#
#	installed ($file, $string);
#
#	search for $string into $file => 1 found / 0 not found

sub backupinstall
{
	my $file = $_[0];
	my $wkdir = $_[1];
	my $storebkp = $_[2];
	my $moddir = $_[3];
	system "/bin/cp -p $wkdir/$file $storebkp/$file";
	system "/bin/cp $moddir/$file $wkdir/$file";
}

sub backup
{
	my $file = $_[0];
	my $wkdir = $_[1];
	my $storebkp = $_[2];
	system "/bin/cp -p $wkdir/$file $storebkp/$file";
}

sub install
{
	my $file = $_[0];
	my $wkdir = $_[1];
	my $moddir = $_[2];
	system "/bin/cp -fp $moddir/$file $wkdir/$file";
}

sub uninstallrestore
{
	my $file = $_[0];
	my $wkdir = $_[1];
	my $storebkp = $_[2];
	system "/bin/cp -p $storebkp/$file $wkdir/$file";
#	system "/bin/rm -f $storebkp/$file";
}

sub uninstall
{
	my $file = $_[0];
	my $wkdir = $_[1];
	system "/bin/rm -f $wkdir/$file";
}

sub easymod
{
	my $targetfile = $_[0];
	my $searchfile = $_[1];
	my $linestodelete = $_[2];
	my $replacefile = $_[3];

	open(TARGET, "$targetfile") or die 'Unable to open target file.';
	my @target = <TARGET>;
	close(TARGET);

	open(SEARCH, "$searchfile") or die 'Unable to open search file';
	my @search = <SEARCH>;
	close(SEARCH);

	open(REPLACE, "$replacefile") or die 'Unable to open replace file.';
	my @replace = <REPLACE>;
	close(REPLACE);

	open(TEMP, ">/tmp/temp") or die 'Unable to open temporary file.';
	flock TEMP, 2;

	my $found = 0;
	my $line;
	foreach $line (@target)
	{
		if ($found == 0)
		{
			if ($line eq "@search")
			{
				$found = 1;
				if ($linestodelete > 0)
				{
					$linestodelete--;
				}
				else {print TEMP "$line"; }
				my $repline;
				foreach $repline (@replace) {print TEMP $repline; }
			}
			else {print TEMP "$line"; }
		}
		else
		{
			if ($linestodelete > 0)
			{
				$linestodelete--;
			}
			else {print TEMP "$line"; }
		}
	}	
	close(TEMP);
	system "/bin/cp /tmp/temp $targetfile";
	system "/bin/rm -f /tmp/temp";
}

sub installed
{
	my $targetfile = $_[0];
	my $searchstring = $_[1];

	open(TARGET, "$targetfile") or die 'Unable to open target file.';
	my @target = <TARGET>;
	close(TARGET);

	my $line;
	foreach $line (@target)
	{
		if ($line eq "$searchstring\n")
		{
			return 1;
		}
	}	
	return 0;
}
