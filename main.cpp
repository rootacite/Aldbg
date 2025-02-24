
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <gtkmm.h>
#include <iostream>
#include <string>
#include <pthread.h>
#include <sys/wait.h>

#include "interface/home.hpp"

#define MAX_LOG_BUFFER_SIZE (1024*1024)

using namespace std;

Glib::RefPtr<HomeWindow> home;

extern void button_attach();
extern void button_exec();

static pthread_t threads[5];

char buffer[MAX_LOG_BUFFER_SIZE];
ssize_t sz = -1;
int pipefd[2] = {0};

void *aldbg_io_handler(void *arg)
{
    int r;

    socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd);
    dup2(pipefd[1], STDOUT_FILENO); // dup pipe write port to stdout

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = pipefd[0];

    int efd = epoll_create1(0);
    epoll_ctl(efd, EPOLL_CTL_ADD, pipefd[0], &ev);


    while(1)
    {
        r = epoll_wait(efd, &ev, 1, 50);
        if(r == -1)perror("epoll_wait()");
        if(r == 1)
        {
            sz = read(pipefd[0], buffer, MAX_LOG_BUFFER_SIZE);
            buffer[sz] = 0;

            char *pStr = strtok(buffer, "\n");
            while(pStr)
            {
                home->logView->add_log_data(pStr);
                pStr = strtok(nullptr, "\n");
            }
        }
    }

    return nullptr;
}

int main()
{
    home = HomeWindow::create();

    //pthread_create(&threads[0], nullptr, aldbg_io_handler, nullptr);

    return home->loop();
}