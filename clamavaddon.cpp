//clear; rm -frv clamavaddon.o ; g++ -g -fPIC -Wall -c clamavaddon.cpp;  g++ -g -fPIC -Wall -lclamav -o clamavaddon clamavaddon.o; date;
//lynx https://man7.org/linux/man-pages/man7/fanotify.7.html
//lynx https://www.clamav.net/documents/libclamav

#include <unistd.h>
#include <stdio.h>
#include <string>
#include <strings.h>
#include <stdlib.h>
#include <iostream>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sstream>
#include <iomanip>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include "clamav.h"
#include <fcntl.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>

using namespace std;

int main(int argc, char *argv[])
{
	cout<<"clamav ADD ON"<<endl;
	
	struct fanotify_event_metadata *metadata;
	struct fanotify_response response;

	int fan_desc;
	char puffer[4096];
	char file_descriptor_pfad[32];
	char pfad_char[PATH_MAX + 1];
	int puffer_laenge = -1 ;
	int link_laenge = -1 ;

	string pfad_string;
	string proc_pfad;

	int rc = -1;
	
	cout<<"Starte LibClamAV"<<endl;
	cl_init(CL_INIT_DEFAULT);
	struct cl_engine *engine;
	unsigned int sigs = 0;
	int ret;
	if((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) 
	{
		printf("cl_init() error: %s\n", cl_strerror(ret));
		return 1;
	}
	if(!(engine = cl_engine_new())) 
	{
		printf("Can't create new engine\n");
		return 1;
	}
	const char *dbdir = cl_retdbdir();
	ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
	ret = cl_engine_compile(engine);
	struct cl_stat dbstat;
	const char *cl_retdbdir(void);
	memset(&dbstat, 0, sizeof(struct cl_stat));
	cl_statinidir(dbdir, &dbstat);
	const char *virname;
	static struct cl_scan_options options = {};
	{
		options.parse |= ~0; // enable all parsers
	}
	
	cout<<"Starte File Monitoring"<<endl;
	
	fan_desc = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
	cout<<"fan desc. fanotify_init#"<<fan_desc<<"#"<<endl;
	
	rc = fanotify_mark(fan_desc, FAN_MARK_ADD | FAN_MARK_MOUNT,FAN_OPEN_PERM | FAN_CLOSE_WRITE, AT_FDCWD,  "/root");
	cout<<"rc fanotify_mark /root#"<<rc<<"#"<<endl;
	
	rc = fanotify_mark(fan_desc, FAN_MARK_ADD | FAN_MARK_MOUNT,FAN_OPEN_PERM | FAN_CLOSE_WRITE, AT_FDCWD,  "/home");
	cout<<"rc fanotify_mark /home#"<<rc<<"#"<<endl;
	
	while(1)

	{
		puffer_laenge = read(fan_desc, puffer, sizeof(puffer));
		
		metadata = (struct fanotify_event_metadata*)&puffer;
		
		while(FAN_EVENT_OK(metadata, puffer_laenge)) 
		{
			sprintf(file_descriptor_pfad, "/proc/self/fd/%d", metadata->fd);
							
			link_laenge = readlink(file_descriptor_pfad, pfad_char, sizeof(pfad_char) - 1);
			
			pfad_char[link_laenge] = '\0';
			
			if((ret = cl_scandesc(metadata->fd, pfad_char,&virname, NULL, engine, &options)) == CL_VIRUS) 
			{

				cout<<"VIRUS GEFUNDEN: "<<virname<<endl;
				response.fd = metadata->fd;
				response.response = FAN_DENY;
				rc = write(fan_desc, &response, sizeof(response));
			}
			else
			{
				response.fd = metadata->fd;
				response.response = FAN_ALLOW;
				rc = write(fan_desc, &response, sizeof(response));
			}

			close(metadata->fd);
			
			metadata = FAN_EVENT_NEXT(metadata, puffer_laenge);
		}
		
		usleep(100000);
	}
			
	return(0);
	
}



