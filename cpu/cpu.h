//
// Created by acite on 5/1/24.
//

#ifndef ALDBG_CPU_H
#define ALDBG_CPU_H

#include <gtkmm.h>
#include <iostream>
#include <string>

void add_row(const std::string &addr,
             const std::string &data,
             const std::string &dasm,
             const std::string &sts
);

void set_row_status(uint64_t index_addr, const std::string& sts);

#endif //ALDBG_CPU_H
