
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <gtkmm.h>
#include <iostream>
#include <string>
#include <pthread.h>
#include <sys/wait.h>

#include "cpu/cpu.h"
#include "log/log.h"

#define MAX_LOG_BUFFER_SIZE (1024*1024)

using namespace std;
using namespace Gtk;

extern void button_attach();
extern void button_exec();

TreeView* codeView;
TreeView* logView;
Glib::RefPtr<ListStore> codeViewStore;
Glib::RefPtr<ListStore> logStore;
Button* bAttach;
Dialog* dialogAttach;
Button* dCancel;
Button* dAttach;
Button* bStop;
Window* MainWindow = nullptr;

static Glib::RefPtr<Application> app;
static pthread_t threads[5];

epoll_event events[5] = {
        { .events = EPOLLIN }   // Event for pipe data
};
epoll_event r_events[5] = {0};
char buffer[MAX_LOG_BUFFER_SIZE];
ssize_t sz = -1;
int pipefd[2] = {0};

void *aldbg_io_handler(void *arg)
{
    int r = pipe2(pipefd, O_CLOEXEC | O_NONBLOCK);
    if(r == -1)
    {
        perror("pipe2()");
        return nullptr;
    }
    dup2(pipefd[1], 1); // dup pipe write port to stdout

    events[0].data.fd = pipefd[0];
    int efd = epoll_create1(0);
    epoll_ctl(efd, EPOLL_CTL_ADD, pipefd[0], &events[0]);


    while(1)
    {
        r = epoll_wait(efd, r_events, 5, 2000);
        if(r == -1)perror("epoll_wait()");
        if(r == 0)continue;

        for(int i=0;i<r;i++)
        {
            if(r_events[i].data.fd == pipefd[0])
            {
                sz = read(pipefd[0], buffer, MAX_LOG_BUFFER_SIZE);
                buffer[sz] = 0;

                char *pStr = strtok(buffer, "\n");
                while(pStr)
                {
                    add_log_data(pStr);
                    pStr = strtok(NULL, "\n");
                }

            }
        }
    }

    return nullptr;
}

bool motion_event(GdkEventMotion* m)
{
    double x = m->x;
    double y = m->y;
    std::cout << "Mouse moved to: (" << x << ", " << y << ")" << std::endl;
    return false; // 事件已被处理
}

void window_init()
{
    ////////////////////////////////////////// register assemblies
    auto builder = Builder::create_from_file("../aldbg.glade");
    builder->get_widget("MainWindow", MainWindow);
    builder->get_widget("code", codeView);
    builder->get_widget("log", logView);
    builder->get_widget("bAttach", bAttach);
    builder->get_widget("dialogAttach", dialogAttach);
    builder->get_widget("dCancel", dCancel);
    builder->get_widget("dAttach", dAttach);
    builder->get_widget("bStop", bStop);
    codeViewStore = Glib::RefPtr<Gtk::ListStore>::cast_dynamic(codeView->get_model());
    logStore      = Glib::RefPtr<Gtk::ListStore>::cast_dynamic(logView->get_model());
    ///////////////////////////////////////////

    app->add_window(*MainWindow);
    MainWindow->show();                 // Show Window

    for(int i=0;i<35;i++)
        add_row(to_string(i * 1000), "DAF", "Fuck", "->");
    set_row_status(2000, "*->");

    ///////////////////////////////////////////////////// register events
    bAttach->signal_clicked().connect([](){
        button_attach();
    });

    dCancel->signal_clicked().connect([](){
        dialogAttach->close();
    });

    dAttach->signal_clicked().connect([](){
        button_exec();
    });

    bStop->signal_clicked().connect([](){

    });

    MainWindow->add_events(Gdk::POINTER_MOTION_MASK);
    /////////////////////////////////////////////////////

    pthread_create(&threads[0], nullptr, aldbg_io_handler, nullptr);
}

int main()
{
    app = Application::create();
    app->signal_activate().connect([](){
       window_init();
    });

    return app->run();
}