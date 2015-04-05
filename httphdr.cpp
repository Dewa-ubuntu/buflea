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


#include "context.h"


//-------------------------------------------------------------------------------------
// All crappy HTTP header parsers I test either crashes either suck in
// resource allocation and handlings strings.
// .. better reinvent the wheel.... (not so profi, but very fast and did not crash yet)

const char* SocksHdr::_host = "Host: ";
const char* SocksHdr::_prox = "Proxy-Connection: ";
const char* SocksHdr::_cont = "Content-Length: ";
const char* SocksHdr::_conn = "CONNECT ";
const char* SocksHdr::_reff = "Referer: ";
const char* SocksHdr::_enco = "Accept-Encoding: ";

size_t SocksHdr::_hlen     = strlen(_host);
size_t SocksHdr::_plen     = strlen(_prox);
size_t SocksHdr::_clen     = strlen(_cont);
size_t SocksHdr::_colen    = strlen(_conn);
size_t SocksHdr::_reflen   = strlen(_reff);
size_t SocksHdr::_enclen   = strlen(_enco);

int SocksHdr::parse()   // <0 error 0 done 1 still to parse
{
#define IS_HOST(b)      (b[0]==_host[0] && b[4]==_host[4] && b[5]==_host[5])
#define IS_PROXY(b)     (b[0]==_prox[0] && b[16]==_prox[16] && b[17]==_prox[17])
#define IS_CONTENT(b)   (b[0]==_cont[0] && b[14]==_cont[14] && b[15]==_cont[15])
#define IS_CONNECT(b)   (b[0]==_conn[0] && b[3]==_conn[3] && b[7]==_conn[7])
#define IS_REFERER(b)   (b[0]==_reff[0] && b[3]==_reff[3] && b[7]==_reff[7])
#define IS_ENCODING(b) (b[0]==_enco[0] && b[3]==_enco[3] && b[14]==_enco[14])



    u_int8_t*   pbuff = (u_int8_t*)_buf.c_str();
    u_int8_t*   start = pbuff;
    u_int8_t    c = '\n';
    size_t      len = _buf.length();
    bool        eoh = false;

    if(len < 18)
    {
        return 0;
    }
    pbuff += (last_len>18)  ? (last_len-18) : 0;

    while(*pbuff)
    {
        switch(*pbuff)
        {
        case '\n':
            if(c=='\r')
            {
                if(eoh)
                {
                    if(hdr_len==0)
                        hdr_len = ((pbuff - start)+1);
                }
                eoh = true;
            }
            break;
        case '\r':
            if(_nhost && 0 == _nhost_end)
            {
                _nhost_end = size_t(pbuff- start);
            }
            else if(_nreferer && 0 == _nreferer_end)
            {
                _nreferer_end = size_t(pbuff- start);
            }
            else if(_nencoding && 0 == _nencoding_end)
            {
                _nencoding_end = size_t(pbuff- start);
            }
            else if(_nprx && 0 == _nprx_end)
            {
                _nprx_end = size_t(pbuff- start);
            }
            if(c!='\n')
                eoh = false;
            break;
        case 'R':
            if(c=='\n' && IS_REFERER(pbuff))
            {
                if(0==_nreferer)
                {
                    pbuff       += _reflen;
                    _nreferer    = size_t(pbuff - start);
                    _nreferer_end = 0;
                }

            }
            break;
        case 'A':
            if(c=='\n' && IS_ENCODING(pbuff))
            {
                if(0==_nencoding)
                {
                    pbuff          += _enclen;
                    _nencoding     = size_t(pbuff - start);
                    _nencoding_end = 0;
                }

            }
            break;
        case 'H':
            if(c=='\n' && IS_HOST(pbuff))
            {
                if(0==_nhost)
                {
                    pbuff   += _hlen;
                    _nhost    = size_t(pbuff - start);
                    _nhost_end = 0;
                }

            }
            break;
        case 'C'://content
            if(c=='\n' )
            {
                if(IS_CONTENT(pbuff))
                {
                    pbuff   += _clen;
                    body_len = atoi((const char*)pbuff);

                }
                else if (IS_CONNECT(pbuff))
                {
                    pbuff       += _colen;
                    _nhost      =  size_t(pbuff - start);
                    _nhost_end  = 0;
                    has_open= true;
                }
            }
            break;
        case 'P': //Proxy
            if(c=='\n' && IS_PROXY(pbuff))
            {
                //"Proxy-Connection: " >
                _nprx = size_t(pbuff - start);
                _nprx_end = _nprx + 6;
                pbuff += _plen;
            }
            break;
        default:
            if(_nhost && 0 == _nhost_end)
            {
                if(*pbuff==' ')
                {
                    _nhost_end = size_t(pbuff - start);
                }
            }
            break;
        }
        c = *pbuff++;
    }
    last_len = pbuff - start;

    if(hdr_len==0)     //need more
    {
        return 0;
    }

    if(len >= (hdr_len + body_len))
    {
#ifdef DEBUG
        _hostaddr = _buf.substr(_nhost, _nhost_end - _nhost);
#endif
        ok=true;
        return 1;
    }
    return 0; //need more data
}

