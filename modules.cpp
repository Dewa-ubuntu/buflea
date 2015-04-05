
#include <dlfcn.h>
#include "tinyclasses.h"
#include <strutils.h>
#include "modules.h"

Modules*  __modules;

Modules::Modules():_imods(0)
{

    char  mod_fname[PATH_MAX];
    getcwd(mod_fname, PATH_MAX);//debug only ???

    //
    // default one
    //
    SoHandler h = dlopen("plugins/libhtml_modd.so", RTLD_NOW);
    if(0 == h)
        h = dlopen("plugins/libhtml_mod.so", RTLD_NOW);
    if(0 == h){
        return;
    }
    cout << "Loading module: libhtml_mod.so \n";
    ++_imods;
    _mods["*"] = new SoEntry(h);

    Mapss&  rm = GCFG->_extmodules;
    MapssIt it = rm.begin();
    for(; it != rm.end(); it++){
        //one per thread but one per extension ????
        const char* ftypes = it->first.c_str(); //debug inspect
        sprintf(mod_fname,"plugins/%s", it->second.c_str());
        if(it->second == "libhtml_mod.so"||it->second == "libhtml_modd.so")
            continue; // loaded by default
        SoHandler h = dlopen(mod_fname, RTLD_NOW);
        if(h != NULL) {
            _mods[it->first] = new SoEntry(h);
            cout << "Loading module: " << mod_fname << "\n";
            ++_imods;
        }else
            cout << mod_fname << ": " << mod_fname << ", "<< dlerror() << "\r\n";
    }//for
}

Modules::~Modules()
{
    SoMapIt it = _mods.begin();
    for(; it != _mods.end(); it++){
        delete it->second;
    }
}

const SoEntry* Modules::getMod(const char* by_name)const
{
    static std::string sstar("*");
    if(!::valid_ptr(by_name)){
        return _mods[sstar];
    }
    SoMapIt it = _mods.begin();
    for(; it != _mods.end(); it++){
        const std::string& pkey = (*it).first;
        if(pkey.find(by_name) != string::npos){
            return (*it).second;
        }
    }
    //allways fallback the html one
    return _mods[sstar];
}


SoEntry::SoEntry(SoHandler ph):_sohndl(ph)
{
    _so_get = (pFn_getFoo)(dlsym(ph,"factory_get"));
    _so_release = (pFn_releaseFoo )(dlsym(ph,"factory_release"));
}

SoEntry::~SoEntry()
{
    dlclose(_sohndl);
}
