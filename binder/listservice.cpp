#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
    
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>

#include <utils/Log.h>
#include <utils/List.h>
#include <utils/StrongPointer.h>

using namespace android;

void listServices()
{
    sp<IBinder> ctx = ProcessState::self()->getContextObject(NULL);
    //sp<IServiceManager> sm = IServiceManager::asInterface(ctx);
    sp<IServiceManager> sm = interface_cast<IServiceManager>(ctx);

    Vector<String16>  services = sm->listServices();
    fprintf(stderr, "lj listservices:\n");
    for (size_t i = 0; i < services.size(); ++i) {
        String8 s(services[i]);
        fprintf(stderr, "\t%s\n", s.string());
    }
}

void dumpActivityState()
{
    const char *ACTIVITY_MANAGER_SERVICE = "activity";
    const char *DUMP_FILE_PATH = "/data/app/dump.txt";

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> amBinder = sm->getService(String16(
                                              ACTIVITY_MANAGER_SERVICE));
    int fd = open(DUMP_FILE_PATH, O_CREAT | O_WRONLY | O_TRUNC, 0777);
    if (fd > -1) {
       Vector<String16>  args;
       amBinder->dump(fd, args);
       amBinder->dump(1, args);
       close(fd);
   }
}

void testBinders()
{
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> amBinder = sm->getService(String16("activity"));

    String16 amItfDescr = amBinder->getInterfaceDescriptor();
    if (amItfDescr == String16("android.app.IActivityManager"))
    {
        fprintf(stderr, "got 'android.app.IActivityManager'\n");
    }

    if (amBinder->isBinderAlive() &&
        amBinder->pingBinder() == NO_ERROR &&
        amBinder->queryLocalInterface(amItfDescr) == NULL)
    {
        fprintf(stderr,"The non-local interface binder is alive\n");
    }

    if ((amBinder->localBinder() == NULL)  && 
        (amBinder->remoteBinder() != NULL)) 
    {
        fprintf(stderr, "we really have a proxy for the remote interface!\n");
    }

    if ((amBinder->remoteBinder()->remoteBinder() != NULL) &&
        (amBinder->remoteBinder() == amBinder->remoteBinder()->remoteBinder()) &&
         amBinder->remoteBinder()->remoteBinder() ==
                        amBinder->remoteBinder()->remoteBinder()->remoteBinder())
    {
        fprintf(stderr, "same remote binder\n");
    }
}

int main(int argc, char *argv[])
{
    int ret = 0;
    
    listServices();
    dumpActivityState();
    testBinders();

    return ret;
}
