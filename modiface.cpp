
#include "listeners.h"
#include "ctxthread.h"
#include <modiface.h>
#include "context.h"

int  Context::socket_write(const char* str)
{
    return socket_write(str, strlen(str));
}

int  Context::socket_write(const char* buff, size_t len)
{
    int sz = _sock.sendall(buff, len);
    if(sz!=0){
        _sock.destroy();
        return 0;
    }
    if(sz>0)++_sendrecs[0];
    _pthread ? _pthread->checkin(0,len):(void)0;
    return sz;
}

int  Context::socket_read(char* buff, size_t len)
{
    int sz = _sock.receive(buff, len);
    if(sz>0)++_sendrecs[0];
    _pthread ? _pthread->checkin(sz,0):(void)0;
    return sz;
}


void    Context::logString(const char*, ...)
{

}
extern Listeners* __pl; //ugly

void    Context::get_report(std::ostringstream& ss)
{
    __pl->get_report(ss);
}

