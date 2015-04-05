/**
# Copyright (C) 2012-2014 Chincisan Octavian-Marius(mariuschincisan@gmail.com) - coinscode.com - N/A
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
*/


#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <iostream>
#include <signal.h>
#include "os.h"
#include "main.h"
#include "config.h"
#include "listeners.h"
#include "ctxqueue.h"
#include "context.h"
#include "threadpool.h"
#include "dnsthread.h"
#include "modules.h"
#include "tasker.h"
#include <strutils.h>

//-----------------------------------------------------------------------------
// /usr/bin/valgrind --tool=memcheck  -v --leak-check=full  --track-origins=yes --show-reachable=yes /path/to/debug

using namespace std;
const static char * __USR_LOCK    = "/tmp/buflea.lock";
const static char * __SYS_LOCK    = "/var/run/buflea.lock";
inline const char* LockFile(){ return getuid() == 0 ? __SYS_LOCK : __USR_LOCK;}
static bool         __owner = false;

//-----------------------------------------------------------------------------
bool __alive = true;
int  __alivethrds=0;

//-----------------------------------------------------------------------------
void ControlC (int i)
{
    __alive = false;
}

//---------------------------------------------------------------------------------------
// broken pipe
void ControlP (int i)
{
}

//-----------------------------------------------------------------------------
int single_instance_dmn(int nargs, char* vargs[]);

//-----------------------------------------------------------------------------

struct GLobalOi{
    ~GLobalOi(){
        if(__owner){
            std::cout << "deleting lock\n";
            ::unlink(LockFile());
        }
    }
    void use(){
        std::cout << "using obj oi\n";
    };
}   __oi;

//-----------------------------------------------------------------------------
int main(int nargs, char * vargs[])
{
    if(!single_instance_dmn(nargs, vargs)) {
        return 0;
    }
    signal(SIGINT,  ControlC);
    signal(SIGABRT, ControlC);
    signal(SIGTERM, ControlC);
    signal(SIGKILL, ControlC);
    signal(SIGTRAP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN); //this is crap

    cout << __VERSION << "\n";

 #ifdef _PERSONAL
//    _authenticate();
 #endif
    ConfPrx   f("buflea.conf");
    do {
        DbAccess    db( f._glb.sessiontime,
                        f._glb.maxrecs,
                        f._glb.banned_ips,
                        f._glb.subscribers,
                        f._glb.admins,
                        f._glb.usercontrol,
                        f._glb.reloadacls,
                        f._glb.hostsfile,
                        f._glb.hostsfilerule);

        tasker      task;
        ThreadPool  tpa(false);
        Listeners   thel(&tpa, &db);
        DnsHtps     thedns(f._glb.domrecs);
        GLobalOi*   po = &__oi;

        po->use();
        task.start_thread();
        tpa.create();
        if(tpa.start_thread()!=0 || db.start_thread()!=0)
        {
            printf("cannot start tpa or db thread \n");
            break;
        }
        sleep(1);
        tpa.set_prio(5);

        GLOGI("STARTING SERVER BUFLEA:" << __VERSION);
        GLOGI("/tmp/buflea.stop (stops server) ");

        thel._listen_spin();

        db.signal_to_stop();
        task.signal_to_stop();

        __dnsssl=0;
    } while(0);
    unlink("/tmp/buflea.stop");
    GLOGI("Destroying. Exitpoint: thread count:"<< __alivethrds);
    return 0;
}

//-----------------------------------------------------------------------------
int is_running()
{
#ifdef DEBUG
    return 0;
#endif
    int pdf = open(LockFile(), O_CREAT | O_RDWR, 0666);
    int rc = ::flock(pdf, LOCK_EX | LOCK_NB);
    if(rc == 0)
    {
        std::cout << "Locking file" << (char*)LockFile() << "\n";
        __owner=true; // is it required !?!
        return 0;
    }
    return  1;

}

//-----------------------------------------------------------------------------
int single_instance_dmn(int nargs, char* vargs[])
{
    bool running = is_running();
    if(nargs!=2) {
        if(running) {
            printf("process already running\n");
            return 0;
        }
        printf("usage: buflea start/stop\n");
    }

    if(nargs==2) {
        if(!strcmp(vargs[1],"stop")) {
            if(running) {
                printf ("stopping\n");
                system("touch /tmp/buflea.stop");
            }
            return 0;
        }

        if(running) {
            printf("process already running\n");
            return 0;
        }

        if(!strcmp(vargs[1],"start")) {
            daemon(1,0);
        }
    }
    return 1;
}
