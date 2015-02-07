/* SysGAR Module for the SmoothWall SUIDaemon                             */
/* Contains functions for managing Guardian Active Response               */
/* (c) 2014 Quartz Crystal Software and wkitty42                          */
/* ---------------------------------------------------------------------- */
/* based on code originally by D.K.Taylor for the Smoothwall SUID daemon  */

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

	int restart_GAR(std::vector<std::string> & parameters, std::string & response);
	int add_VRTCautoupdate(std::vector<std::string> & parameters, std::string & response);
	int del_VRTCautoupdate(std::vector<std::string> & parameters, std::string & response);
	int add_VRTautoupdate(std::vector<std::string> & parameters, std::string & response);
	int del_VRTautoupdate(std::vector<std::string> & parameters, std::string & response);
	int add_ETautoupdate(std::vector<std::string> & parameters, std::string & response);
	int del_ETautoupdate(std::vector<std::string> & parameters, std::string & response);
	int start_GAR(std::vector<std::string> & parameters, std::string & response);
	int stop_GAR(std::vector<std::string> & parameters, std::string & response);
	int create_sidmap(std::vector<std::string> & parameters, std::string & response);
}

int load(std::vector<CommandFunctionPair> & pairs)
{
	/* CommandFunctionPair name("command", "function"); */
	CommandFunctionPair start_GAR_function("GARstart", "start_GAR", 0, 0);
	CommandFunctionPair stop_GAR_function("GARstop", "stop_GAR", 0, 0);
	CommandFunctionPair restart_GAR_function("GARrestart", "restart_GAR", 0, 0);
	CommandFunctionPair create_sidmap_function("createsidmap", "create_sidmap", 0, 0);
	CommandFunctionPair add_ETautoupdate_function("addETautoupdate", "add_ETautoupdate", 0, 0);
	CommandFunctionPair del_ETautoupdate_function("delETautoupdate", "del_ETautoupdate", 0, 0);
	CommandFunctionPair add_VRTautoupdate_function("addVRTautoupdate", "add_VRTautoupdate", 0, 0);
	CommandFunctionPair del_VRTautoupdate_function("delVRTautoupdate", "del_VRTautoupdate", 0, 0);
	CommandFunctionPair add_VRTCautoupdate_function("addVRTCautoupdate", "add_VRTCautoupdate", 0, 0);
	CommandFunctionPair del_VRTCautoupdate_function("delVRTCautoupdate", "del_VRTCautoupdate", 0, 0);

	pairs.push_back(start_GAR_function);
	pairs.push_back(stop_GAR_function);
	pairs.push_back(restart_GAR_function);
	pairs.push_back(create_sidmap_function);
	pairs.push_back(add_ETautoupdate_function);
	pairs.push_back(del_ETautoupdate_function);
	pairs.push_back(add_VRTautoupdate_function);
	pairs.push_back(del_VRTautoupdate_function);
	pairs.push_back(add_VRTCautoupdate_function);
	pairs.push_back(del_VRTCautoupdate_function);

	return 0;
}

int restart_GAR(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	error += stop_GAR(parameters, response);

	if (!error)
		error += start_GAR(parameters, response);

	if (!error)
		response = "GAR restarted successfully.";

	return error;
}


int stop_GAR(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;
//	std::vector<std::string>ipb;	
	response = "GAR process terminated.";

	killunknownprocess("GAR");

//	ipbatch(ipb);
		
	return 0;
}

int start_GAR(std::vector<std::string> & parameters, std::string & response)
{

	int error = 0;
//	std::vector<std::string>ipb;
	ConfigVAR settings("/var/smoothwall/mods/GAR/settings");

	if (settings["ENABLE_GUARD"] == "on")
	{
		response = "GAR process started.";

		error = simplesecuresysteml("/var/smoothwall/mods/GAR/usr/bin/GAR", NULL, NULL);
	
		if (error)
			response = "GAR start failed!";
		else
			response = "GAR started successfully.";
	}
	return error;
}

int create_sidmap(std::vector<std::string> & parameters, std::string & response)
{

	int error = 0;

	response = "Creating SID msg map";

	error = simplesecuresysteml("/var/smoothwall/mods/GAR/usr/bin/make-sidmap.pl", NULL, NULL);
	
	if (error)
		response = "Creation of SID msg map failed!";
	else
		response = "Creation of SID msg map successful.";

	return error;
}

int add_ETautoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Enabling ET snort rules autoupdater.";

	error = simplesecuresysteml("/var/smoothwall/mods/GAR/ETautoupdinst.sh", NULL, NULL);

	if (error)
		response = "Enable ET snort rules autoupdater failed!";
	else
		response = "Enable ET snort rules autoupdater successful!";

	return error;
}

int del_ETautoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Disabling ET snort rules autoupdater.";

	error = simplesecuresysteml("/var/smoothwall/mods/GAR/ETautoupduninst.sh", NULL, NULL);

	if (error)
		response = "Disable ET snort rules autoupdater failed!";
	else
		response = "Disable ET snort rules autoupdater successful!";

	return error;
}

int add_VRTautoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Enabling VRT snort rules autoupdater.";

	error = simplesecuresysteml("/var/smoothwall/mods/GAR/VRTautoupdinst.sh", NULL, NULL);

	if (error)
		response = "Enable VRT snort rules autoupdater failed!";
	else
		response = "Enable VRT snort rules auto updater successful!";

	return error;
}

int del_VRTautoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Disabling VRT snort rules autoupdater.";

	error = simplesecuresysteml("/var/smoothwall/mods/GAR/VRTautoupduninst.sh", NULL, NULL);

	if (error)
		response = "Disable VRT snort rules autoupdater failed!";
	else
		response = "Disable VRT snort rules autoupdater successful!";

	return error;
}

int add_VRTCautoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Enabling VRT Community snort rules autoupdater.";

	error = simplesecuresysteml("/var/smoothwall/mods/GAR/VRTCautoupdinst.sh", NULL, NULL);

	if (error)
		response = "Enable VRT Community snort rules autoupdater failed!";
	else
		response = "Enable VRT Community snort rules auto updater successful!";

	return error;
}

int del_VRTCautoupdate(std::vector<std::string> & parameters, std::string & response)
{
	int error = 0;

	response = "Disabling VRT Community snort rules autoupdater.";

	error = simplesecuresysteml("/var/smoothwall/mods/GAR/VRTCautoupduninst.sh", NULL, NULL);

	if (error)
		response = "Disable VRT Community snort rules autoupdater failed!";
	else
		response = "Disable VRT Community snort rules autoupdater successful!";

	return error;
}
