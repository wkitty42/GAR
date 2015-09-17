%baseabouttext = (
%baseabouttext,

'/var/smoothwall/mods/GAR/httpd/cgi-bin/ids.cgi' => 'Enable the Snort IDS service to detect potential security breach attempts from outside your network.<br>Note that Snort <strong>does not</strong> prevent these attempts! It only notifies you about them.<br><br>See "help" (above right) for important information about acquiring rules sets for snort to use.',
'/var/smoothwall/mods/GAR/httpd/cgi-bin/gar.cgi' => "Enable GAR (Guardian Active Response) service to actively block and manage blocked IPs based on snort alerts.<br>NOTE: <i>For GAR to do any useful work, snort should be enabled and running.</i><hr>Configure GAR's settings and Ignored IPs for your system.<br>NOTE: you <strong>MUST</strong> tune snort's rules and GAR's settings to your network's needs! This cannot be stressed enough!",
'/var/smoothwall/mods/GAR/httpd/cgi-bin/gartool.cgi' => 'Edit and maintain oinkmaster options for snort rules management.',
'/var/smoothwall/mods/GAR/httpd/cgi-bin/garstats.cgi' => 'This page provides links to snort stats that are generated at regular intervals. Just click on the link for the time period you are interested in.',
);

1;
