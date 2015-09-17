#!/usr/bin/perl
#
# This code is distributed under the terms of the GPL
#
# (c) Tiago Freitas Leal
#
# uninstall script for Guardian Reactive Firewall

use lib "/usr/lib/smoothwall";
use header qw(:standard);
use Config::Patch;

# # # # # # # # # # # #
# handle file copying #
# # # # # # # # # # # #

#	$storebkp =	where to store backup of the files that are changed by your mod
#	$moddir =	where your mod files are
#	$wkdir =	where you are changing files (backup from and copy to)
#
#	backupinstall ($file ,$wkdir ,$storebkp ,$moddir);
#	backup ($file ,$wkdir ,$storebkp);
#	install ($file ,$wkdir ,$moddir);
#	uninstallrestore ($file ,$wkdir ,$storebkp);
#	uninstall ($file  ,$wkdir);

print "Uninstalling Guardian mod\n";

my $response;
print "Do you wish to save your guardian log files?\n";
print "Enter [y] or [n]:";
$response = <STDIN>;
chomp $response;

until ( $response eq "y" or $response eq "n" )
{ do
	print "That is not a valid response. Please try again.\n";
	print "Enter [y] or [n]:";
	chomp ( $response = <STDIN> );
}

if ( $response eq "n" ) {
	if (-e "/var/log/guardian.bak/") { system ("/bin/rm -rdf /var/log/guardian.bak/"); }
	if (-e "/var/log/guardian/") { system ("/bin/rm -rdf /var/log/guardian/"); }
}

unlink ("/usr/lib/smoothwall/services/guardian");
if (-e "/usr/local/bin/restartguardian") { unlink ("/usr/local/bin/restartguardian"); }
unlink ("/usr/local/sbin/guardian.pl");
unlink ("/etc/logrotate.d/guardian");
unlink ("/etc/guardian.conf");
unlink ("/etc/guardian.ignore");
unlink ("/var/smoothwall/mods/guardian/installed");
unlink ("/httpd/cgi-bin/gar-tracker.cgi");
unlink ("/httpd/cgi-bin/logs.cgi/guardian.dat");
unlink ("/usr/lib/smoothwall/menu/5000_Logs/3001_guardian.list");
system ("/bin/rm -rdf /var/smoothwall/guardian/");

# # # # # # # # # # # #
# restore   backups   #
# # # # # # # # # # # #

my $bkp = '/var/smoothwall/mods/guardian/backup';

$dir = '/httpd/cgi-bin';
&uninstallrestore ('ids.cgi' ,$dir ,$bkp);
&uninstallrestore ('ipblock.cgi' ,$dir ,$bkp);

$dir = '/usr/lib/smoothd';
&uninstallrestore ('sysguardian.so' ,$dir ,$bkp);

$dir = '/httpd/html/help';
&uninstallrestore ('ids.cgi.html.en', $dir, $bkp);

$dir = '/httpd/html/ui/js';
&uninstallrestore ('script.js', $dir, $bkp);

# # # # # # # # # # # #
# handle file editing #
# # # # # # # # # # # #

my $sysinit = "/etc/rc.d/rc.sysinit";
my $statuscgi = "/httpd/cgi-bin/status.cgi";
my $updatered = "/etc/rc.d/rc.updatered";

my $patcher = Config::Patch->new(
        file => $statuscgi,
        key  => "gar",
        );
$patcher->remove();

$patcher = Config::Patch->new(
        file => $updatered,
        key  => "gar",
        );
$patcher->remove();

$patcher = Config::Patch->new(
        file => $sysinit,
        key  => "gar",
        );
$patcher->remove();

$response = '';
print "Do you wish to delete the guardian mod directory?\n";
print "Enter [y] or [n]:";
$response = <STDIN>;
chomp $response;

until ( $response eq "y" or $response eq "n" )
{ do
	print "That is not a valid response. Please try again.\n";
	print "Enter [y] or [n]:";
	chomp ( $response = <STDIN> );
}

if ( $response eq "y" ) {
	print "Removing guardian mod directory...\n";
	system("/bin/rm -rdf /var/smoothwall/mods/guardian/");
}

$response = '';
print "The system needs to be rebooted for changes to take effect.\n \n";
print "Please enter [y] to reboot system now or enter [n] to reboot later.\n \n";
print "Enter [y] or [n]:";
$response = <STDIN>;
chomp $response;

until ( $response eq "y" or $response eq "n" )
{ do
	print "That is not a valid response. Please try again.\n";
	print "Enter [y] or [n]:";
	chomp ( $response = <STDIN> );
}

if ( $response eq "n" ) {
	print "Guardian mod uninstall complete\n \n";
	print "Please remember to reboot your system later for changes to take effect\n";
	print "Please post in the SmoothWall 3.0 Homebrew Forum for any help\n \n";
} elsif ($response eq "y" ) {
	print "Guardian mod uninstall is complete\n \n";
	print "Please post in the SmoothWall 3.0 Homebrew Forum for any help\n \n";
	system("/usr/bin/smoothcom systemrestart");
}

print "Done...\n";

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
	system "/bin/cp -p $moddir/$file $wkdir/$file";
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
