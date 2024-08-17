//
// Created by acite on 5/1/24.
//

#include <ctime>
#include <cstring>
#include <gtkmm.h>
#include <unistd.h>
#include <fcntl.h>
#include "log.h"
#include <pthread.h>

using namespace Gtk;
using namespace std;

extern Glib::RefPtr<ListStore> logStore;

void add_log_data(const std::string& data)
{
    auto mm = logStore->append();
    Gtk::TreeModel::Row row = *mm;

    time_t currentTime;
    time(&currentTime);
    tm* localTime = localtime(&currentTime);

    char time_str[64];
    sprintf(time_str, "[%d:%d:%d]", localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
    string cppstrtime = time_str;

    row.set_value(0, cppstrtime);
    row.set_value(1, data);
}