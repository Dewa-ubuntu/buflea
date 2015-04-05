/*
    Marius C. 2012
*/
#ifndef ContextSP_H
#define ContextSP_H
/*
    context secured preconfigured to connect to preconfigured host
*/
#include <list>
//-----------------------------------------------------------------------------
class ContextSP : public Context
{
public:
    ContextSP(const Conf::Ports* pconf, tcp_xxx_sock& s, SSL_CTX* pslctx);
    virtual ~ContextSP();
protected:
    int  _r_send_header();
    int  _s_send_reply(u_int8_t code);
    int  _parse_header();
    int  _empty_rock();
    int  _connect_to_host();
    int  _sr_read_write();
    int  _sr_http_read_write();
    virtual void    send_exception(const char* desc);
private:
    int  _pending_hdr();
    int  _get_from_rock();
    int  _overwrite_connection(const AddrPort& ap);
private:
    AddrPort _rip;
    bool     _sck_ssl_connect;
    time_t   _tflush;
    int      _loops;
};


#endif // ContextSP_H
