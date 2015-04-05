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

#include "tcppipe.h"
#include "configprx.h"
#include "context.h"

//-----------------------------------------------------------------------------
int TcpPipe::sendall(const u_int8_t* buff, int length, int tout)
{
    if(_ssl)
    {
        int   shot, sent=0,trys=10;

        while(length>0 && --trys>0)
        {
            shot = SSL_write(_ssl, buff + sent, length);
            int serr = SSL_get_error(_ssl,shot);

            switch (serr)
            {
				case SSL_ERROR_NONE:
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_X509_LOOKUP:
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
				case SSL_ERROR_ZERO_RETURN:
                    trys=-1;
                    break;
			}
			if(shot>0)
			{
                length-=shot;
                sent+=shot;
			}
			usleep(0xff);
        }
        return length;
    }
    return tcp_cli_sock::sendall((unsigned char*)buff, length, tout);
}

bool TcpPipe::ssl_pre_accept(const Ctx* pc)
{
    if(0==_ssl)
    {
        _ssl = SSL_new(pc->_pcli_isssl);
        SSL_set_fd(_ssl, socket());
        set_blocking(pc->_pconf->hostisssl==2 ? 1 : 0);
        return true;
    }
    return false;
}

int TcpPipe::_handle_ssl_error(int serr, int syserr, const char* op)const
{
    switch (serr)
    {
        case SSL_ERROR_NONE:
            return 1;
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_X509_LOOKUP:
            return -1;
        case SSL_ERROR_SYSCALL:
            if(syserr==EAGAIN)
                return -1;
        case SSL_ERROR_SSL:
            GLOGE("Error:" << op <<": " << sslNerror(_ssl));
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            return 0;
        default:
            GLOGE("Error:" << op <<": " << sslNerror(_ssl));
            return 0;
            break;
    }
    return 1;
}

//-----------------------------------------------------------------------------
int TcpPipe::receive(u_int8_t* buff, int length)
{
    int rd;
    if(_ssl)
    {
        //assert(pc->_pconf->clientisssl==2 ? is_blocking()==1  : is_blocking()==0);
        rd = SSL_read(_ssl, buff, length);
        if(rd>0)
        {
            buff[rd]=0;    // ok
            return rd;
        }
        return _handle_ssl_error(SSL_get_error(_ssl,rd), errno,"R");
    }
    rd = tcp_cli_sock::receive(buff, length, 0, 0);
    if(rd>0) buff[rd]=0;
    return rd; //return 0 connclosed, -1 no bytes, >0 bytes received
}


int TcpPipe::ssl_accept(const Ctx* pc)
{
    assert(pc->_pconf->hostisssl==2 ? is_blocking()==1  : is_blocking()==0);
    int r = SSL_accept(_ssl);
    return _handle_ssl_error(SSL_get_error(_ssl,r), errno,"SSL_accept");
}

bool TcpPipe::ssl_pre_connect(const Ctx* pc)
{
    if(0==_ssl)
    {
        _ssl = SSL_new(pc->_phost_isssl);
        if(_ssl)
        {
            SSL_set_fd(_ssl, socket());
            set_blocking(pc->_pconf->hostisssl==2 ? 1 : 0);
            return true;
        }
    }
    return false;
}


int TcpPipe::ssl_connect(const Ctx* pc)
{
    assert(_ssl);
    assert(pc->_pconf->clientisssl==2 ? is_blocking()==1  : is_blocking()==0);

    int rc = SSL_connect(_ssl);
    int rv = _handle_ssl_error(SSL_get_error(_ssl,rc), errno,"SSL_Connect");
    if(rv==1)
        tcp_cli_sock::setconnected();
    return rv;
}









