//
// Created by acite on 5/1/24.
//

#include <gtkmm.h>

using namespace Gtk;

extern Button* bAttach;
extern Dialog* dialogAttach;
extern Window* MainWindow;

void button_attach()
{
    dialogAttach->show();
}

void button_exec()
{
    int fk = fork();
    if(fk == 0)
    {
        execl("/usr/bin/netstat", "netstat" ,"-tupln", NULL);
        return;
    }
}