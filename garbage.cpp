//-----------------------------------------------------------------------------
static __idd=0;
int __resource=0;
    ManyViewers    _m;
class TestThread : public OsThread
{
    int _lid;
public:
    TestThread()
    {
       _lid = __idd++;
    }
protected:

    virtual void thread_main()
    {

        while(__alive)
        {
            if(_lid==0)
            {
                _m.paint();
                printf("----------- write %d{\n", __resource);
                __resource++;
                sleep(3);
                printf("----------- write %d} \n", __resource);
                _m.done();
                sleep(2);
            }
            else
            {
                ManyViewers::Read r(_m);
                printf("thread : %d, r-> %d \n", _lid, __resource);

            }

            if(_lid!=0)
                usleep(10000);

        }
    }
};
