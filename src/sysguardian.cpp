/* SysIM Module for the SmoothWall SUIDaemon                              */
/* Contains functions relating to the management of the P3Scan            */
/* (c) 2005 SmoothWall Ltd                                                */
/* ---------------------------------------------------------------------- */
/* Original Author : D.K.Taylor                                           */

/* include the usual headers.  iostream gives access to stderr (cerr)     */
/* module.h includes vectors and strings which are important              */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>

#include "module.h"
#include "ipbatch.h"
#include "setuid.h"

extern "C" {
	int load(std::vector<CommandFunctionPair> & );

	int restart_guardian(std::vector<std::string> & parameters, std::string & response);
	int uninstall_autoupdate(std::vector<std::string> & parameters, std::string & response);
	int install_autoupdate(std::vector<std::string> & parameters, std::string & response);
	int   start_guardian(std::vector<std::string> & parameters, std::string & response);
	int    stop_guardian(std::vector<std::string> & parameters, std::string & response);
	int	create_sidmap(std::vector<std::string> & parameters, std::string & response);
}

int load(std::vector<CommandFunctionPair> & pairs)
{
	/* CommandFunctionPair name("command", "function"); */
	CommandFunctionPair restart_guardian_function("guardianrestart", "restart_guardian", 0, 0);
	CommandFunctionPair uninstall_autoupdate_function("autoupduninstall", "uninstall_autoupdate", 0, 0);
	CommandFunctionPair install_autoupdate_function("autoupdinstall", "install_autoupdate", 0, 0);
	CommandFunctionPair   start_guardian_function("guardianstart",     "start_guardian", 0, 0);
	CommandFunctionPair    stop_guardian_function("guardianstop",       "stop_guardian", 0, 0);
	CommandFunctionPair    create_sidmap_function("createsidmap",        "create_sidmap", 0, 0);

	pairs.push_back(restart_guardian_function);
	pairs.push_back(uninstall_autoupdate_function);
	pairs.push_back(install_autoupdate_function);
	pairs.push_back(  start_guardian_function);
	pairs.push_back(   stop_guardian_function);
	pairs.push_back(   create_sidmap_function);

	return 0;
}

int restart_guardian(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	error += stop_guardian(parameters, response);

	if (!error)
		error += start_guardian(parameters, response);

	if (!error)
		response = "Guardian Restart Successful";

	return error;
}


int stop_guardian(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;
	std::vector<std::string>ipb;	
	response = "Guardian Process Terminated";

	killunknownprocess("guardian.pl");

	ipbatch(ipb);
		
	return 0;
}

int start_guardian(std::vector<std::string> & parameters, std::string & response)
{

	int error = 0;
	std::vector<std::string>ipb;
	ConfigVAR settings("/var/smoothwall/snort/settings");

	if (settings["ENABLE_GUARD"] == "on")
	{
		response = "Guardian Process started";

		error = simplesecuresysteml("/usr/local/sbin/guardian.pl", NULL, NULL);
	
		error = ipbatch(ipb);

		if (error)
			response = "Guardian Start Failed!";
		else
			response = "Guardian Start Successful";
	}
	return error;
}

int create_sidmap(std::vector<std::string> & parameters, std::string & response)
{

	int error = 0;

	response = "Creating SID msg map";

	error = simplesecuresysteml("/usr/local/sbin/make-sidmap.pl", NULL, NULL);
	
	if (error)
		response = "Creation of SID msg map Failed!";
	else
		response = "Creation of SID msg map Successful";

	return error;
}

int install_autoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Installing snort rules auto update";

	error = simplesecuresysteml("/var/smoothwall/mods/guardian/modfiles/autoupdinst.sh", NULL, NULL);

	if (error)
		response = "Installation of snort rules auto updater failed!";
	else
		response = "Installation of snort rules auto updater successful!";

	return error;
}

int uninstall_autoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Uninstalling snort rules auto update";

	error = simplesecuresysteml("/var/smoothwall/mods/guardian/modfiles/autoupduninst.sh", NULL, NULL);

	if (error)
		response = "Uninstallation of snort rules auto updater failed!";
	else
		response = "Uninstallation of snort rules auto updater successful!";

	return error;
}
