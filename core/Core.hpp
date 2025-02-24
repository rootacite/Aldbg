//
// Created by acite on 5/1/24.
//

#ifndef _H_CORE
#define _H_CORE 1

#include <gtkmm.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "MemoryMap.hpp"
#include <capstone/capstone.h>

#include <fstream>
#include <libelfin/elf/elf++.hh>
#include <map>
#include <unordered_map>

#include <capstone/capstone.h>

#define WORD_SIZE 8

enum Msg{
    MSG_PAUSE       = 0,
    MSG_STOP        = 1,
    MSG_CONTINUE    = 2,
    MSG_STARTUP     = 3,
    MSG_REG         = 4,
    MSG_QUIT        = 5,
    MSG_LOG         = 6,
    MSG_ASM         = 7,
    MSG_TITLE       = 8,
    MSG_STEPINTO    = 9,
    MSG_MEMORY      = 10,
    MSG_SELECT      = 11,
    MSG_CURRENTSYMBOL     = 12,
    MSG_RESTART     = 13,
    MSG_BREAK       = 14,
    MSG_STEPOVER    = 15,
    MSG_SYMBOLS     = 16,
    MSG_SWITCHSYMBOL= 17,
    MSG_NONSYM      = 18,
    MSG_PARSE       = 19,
    MSG_INSYM       = 20,
    MSG_DELBREAK    = 21,
    MSG_SWITCHMODULE= 22,
    MSG_GETBREAKS   = 23,
    MSG_CALLSTACK   = 24,
    MSG_BREAKONCE   =  25
};

struct DebugCommand
{
    char id;
    void* param;
};

struct BreakPoint
{
    uint64_t addr;
    bool once;
    uint64_t origin;
    uint16_t size;

    bool enable;
};

struct Symbol{
    char name[255];
    uint64_t address;
    uint64_t size;
    uint64_t base;
};

struct CallstackStruct
{
    uint64_t callPoint;
    uint64_t stackBase;
    Symbol symbol;
    char module[255];
    int depth;
};

class Core{
private:
    std::map<uint64_t, BreakPoint> _breakPoints;
    int _ep = -1;
    uint64_t _lastRip = 0;
    int _counter = 0;
    uint64_t _needToRestore = 0;

public:
    const uint64_t int3 = 0xCCCCCCCCCCCCCCCC;

    int pipe = -1;
    int remotePipe = -1;

    user_regs_struct regs;
    std::vector<Symbol> symbols;
    std::vector<Symbol> staticSymbols;
    std::unordered_map<std::string, std::vector<Symbol>> symbolMap;

    Symbol currentSymbol{};

    void PeekTexts(uint64_t* data, uint64_t words) const
    {
        auto addr = _lastRip;

        for(uint64_t i=0;i<words;i++)
        {
            data[i] = ptrace(PTRACE_PEEKTEXT, _process, addr + i * 8, NULL);
        }
    }

    void PeekTextsFrom(uint64_t* data, uint64_t words, uint64_t address) const
    {
        for(uint64_t i=0;i<words;i++)
        {
            data[i] = ptrace(PTRACE_PEEKTEXT, _process, address + i * 8, NULL);
        }
    }
    /*
    void PeekTextsFrom(uint64_t address, uint64_t size)
    {
        delete[] codeData;

        codeSize = size;
        codeData = new uint8_t[codeSize + 16];
        codeAddr = address;
        for(uint64_t p = codeAddr, offset = 0; p < codeAddr + codeSize; p += WORD_SIZE, offset += WORD_SIZE)
        {
            *(uint64_t*)(codeData + offset) = ptrace(PTRACE_PEEKDATA, _process, p, nullptr);
        }
    }

    void RestoreCode()
    {
        for(auto k: _breakPoints)   // Repair Breakpoint code
        {
            if(k.second.enable && k.second.addr >= codeAddr && k.second.addr < codeAddr + codeSize)
            {
                uint64_t localOffset = k.second.addr - codeAddr;
                auto px = reinterpret_cast<uint64_t*>(codeData + localOffset);
                uint64_t mask = 0xFFFFFFFFFFFFFFFF << k.second.size * 8;

                *px = (k.second.origin & (~mask)) | ((*px) & mask);
            }
        }
    }
    */
    uint64_t GetBaseAddress()
    {
        if(_map == nullptr) return 0;

        for(int i=0;i<_map->Size();i++)
        {
            auto j = _map->GetItem(i);
            if(_path == j.path)
            {
                return j.startAddress;
            }
        }
        return 0;
    }

    uint64_t GetBaseAddress(const std::string& module)
    {
        if(_map == nullptr) return 0;

        for(int i=0;i<_map->Size();i++)
        {
            auto j = _map->GetItem(i);
            if(module == j.path)
            {
                return j.startAddress;
            }
        }
        return 0;
    }

    uint64_t GetEndAddress(const std::string& module)
    {
        if(_map == nullptr) return 0;
        uint64_t endAddr = 0;

        for(int i=0;i<_map->Size();i++)
        {
            auto j = _map->GetItem(i);
            if(module == j.path)
            {
                endAddr = j.endAddress;
            }
        }
        return endAddr;
    }

    uint64_t GetEntryPoint()
    {
        int fd = open(_path.c_str(), O_RDONLY);
        if(fd < 0) return 0;

        elf::elf ef(elf::create_mmap_loader(fd));
        return ef.get_hdr().entry;
    }

    std::vector<Symbol> GetSymbols(const std::string& module)
    {
        std::vector<Symbol> tr;
        std::map<std::string, Symbol> r;

        uint64_t lbase = GetBaseAddress(module);
        uint64_t ebase = GetEndAddress(module);

        if(symbolMap.contains(module))
        {
            tr = symbolMap[module];
        }
        else
        {
            int fd = open(module.c_str(), O_RDONLY);
            if(fd < 0) return {};

            elf::elf ef(elf::create_mmap_loader(fd));
            for (const auto& section : ef.sections()) {
                if (section.get_hdr().type == elf::sht::symtab) {

                    const auto& lsymbols = section.as_symtab();
                    for (const auto& symbol : lsymbols) {
                        if (symbol.get_data().type() == elf::stt::func && symbol.get_data().value != 0) {
                            // A symbol with zero address maybe an extern symbol in (.so)
                            // We will not place it in local module symbol list
                            // Because we fill find its body in the symbol table of another modules
                            Symbol h{};
                            strcpy(h.name, symbol.get_name().c_str());
                            h.address = symbol.get_data().value;
                            h.size = symbol.get_data().size;
                            h.base = lbase;
                            r.emplace(symbol.get_name(), h);
                        }
                    }
                }
            }

            for (const auto& section : ef.sections()) {
                if (section.get_hdr().type == elf::sht::dynsym) {
                    const auto& lsymbols = section.as_symtab();
                    for (const auto& symbol : lsymbols) {
                        if (symbol.get_data().type() == elf::stt::func && symbol.get_data().value != 0 && (!r.contains(symbol.get_name()))) {
                            Symbol h{};
                            strcpy(h.name, symbol.get_name().c_str());
                            h.address = symbol.get_data().value;
                            h.size = symbol.get_data().size;
                            h.base = lbase;
                            r.emplace(symbol.get_name(), h);
                        }
                    }
                }
            }
            for(const auto& j : r)
            {
                tr.emplace_back(j.second);
            }

            for(auto &k : tr)
            {
                if(k.size == 0) // Unmarked Symbol
                {
                    // Find a symbol following behind it
                    uint64_t addr = 0xffffffffffffffff;
                    for(auto &j : tr)
                    {
                        if(j.address > k.address && j.address < addr) addr = j.address;
                    }

                    if(addr != 0xffffffffffffffff){ k.size = addr - k.address; continue; }

                    // Found no Symbol
                    // Set its size to the end of its section
                    for (const auto& section : ef.sections())
                    {
                        if(k.address > section.get_hdr().addr && k.address < section.get_hdr().addr + section.size())
                        {
                            k.size = section.get_hdr().addr + section.size() - k.address;
                        }
                    }
                }
            }

            symbolMap.emplace(module, tr);
        }

        for(const auto &k : staticSymbols)
        {
            if(k.address >= lbase && k.address < ebase)
            {
                bool within = false;
                for(const auto &j : tr)
                {
                    if(k.address >= j.address + j.base && k.address < j.address + j.size + j.base)
                    {
                        within = true;
                        break;
                    }
                }
                if(!within) tr.emplace_back(k);
            }
        }

        return tr;
    }

    void InsertBreakPoint(uint64_t addr, bool once = true)
    {
        if(_breakPoints.contains(addr)) return;

        auto ins = disassemblyFrom(addr, 1, 0);

        BreakPoint bp{};
        bp.once = once;
        bp.addr = addr;
        bp.origin = ptrace(PTRACE_PEEKTEXT, _process, addr, NULL);
        bp.size = ins[0].size;
        if(bp.size > 8) bp.size = 8;
        bp.enable = true;

        uint64_t mask = 0xFFFFFFFFFFFFFFFF << bp.size * 8;

        uint64_t int3_data = (bp.origin & mask) | (int3 & (~mask));
        ptrace(PTRACE_POKETEXT, _process, addr, int3_data);

        _breakPoints.emplace(bp.addr, bp);
    }

    void DisableBreakPoint(uint64_t addr)
    {
        if(!_breakPoints.contains(addr)) return;

        _breakPoints[addr].enable = false;

        uint64_t origin = ptrace(PTRACE_PEEKTEXT, _process, addr, NULL);
        uint64_t mask = 0xFFFFFFFFFFFFFFFF << _breakPoints[addr].size * 8;

        ptrace(PTRACE_POKETEXT, _process, addr,
               (_breakPoints[addr].origin & (~mask)) | (origin & mask));
    }

    void RestoreBreakPoint(uint64_t addr)
    {
        if(!_breakPoints.contains(addr)) return;

        _breakPoints[addr].enable = true;
        uint64_t origin = ptrace(PTRACE_PEEKTEXT, _process, addr, NULL);

        uint64_t mask = 0xFFFFFFFFFFFFFFFF << _breakPoints[addr].size * 8;
        uint64_t int3_data = (origin & mask) | (int3 & (~mask));

        ptrace(PTRACE_POKETEXT, _process, addr, int3_data);
    }

    void DeleteBreakPoint(uint64_t addr)
    {
        if(!_breakPoints.contains(addr)) return;

        DisableBreakPoint(addr);
        _breakPoints.erase(addr);
    }

    bool ContainsBreakPoint(uint64_t addr)
    {
        return _breakPoints.contains(addr);
    }

    std::vector<BreakPoint> GetBreakpoints()
    {
        std::vector<BreakPoint> r;
        for(const auto &k : _breakPoints)
        {
            r.emplace_back(k.second);
        }
        return r;
    }

    void TryContinue()
    {
        if(_needToRestore == 0)
            ptrace(PTRACE_CONT, _process, NULL, NULL);
        else
        {
            ptrace(PTRACE_SINGLESTEP, _process, NULL, NULL);
            _temporaryStop = true;
        }
    }

    void queueMessage(char id, void* param) const
    {
        DebugCommand msg{id, param};
        if(pipe != -1)
        {
            write(remotePipe, &msg, sizeof(DebugCommand));
        }
    }

    static bool ContainerContains(const std::vector<std::string>& c, const std::string& e)
    {
        for(const auto &k : c)
        {
            if(k == e) return true;
        }
        return false;
    }

    /// disassembly from an address
    /// \param address
    /// \param cc
    /// \param sz cc and sz cannot be both 0 at the same time
    /// \return
    [[nodiscard]] std::vector<cs_insn> disassemblyFrom(uint64_t address, int cc, uint32_t sz, const std::vector<std::string>& end = {}, bool make = false)
    {
        if(cc == 0 && sz == 0) return {};
        uint64_t originAddress = address;

        csh handle;
        cs_insn *insn;
        size_t count;
        std::vector<cs_insn> r;
        uint64_t data[4];

        if(!cc) cc = INT_MAX;
        if(!sz) sz = 0xFFFFFFFF;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            return {};
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

        for(int i=0, p=0;i<cc && p < sz;i++)
        {
            PeekTextsFrom(data, 4, address);
            for(auto k: _breakPoints)   // Repair Breakpoint code
            {
                if(k.second.enable && k.second.addr == address)
                {
                    uint64_t mask = 0xFFFFFFFFFFFFFFFF << k.second.size * 8;
                    data[0] = (k.second.origin & (~mask)) | ((data[0]) & mask);
                }
            }

            count = cs_disasm(handle, (uint8_t*)data, 32, address, 1, &insn);
            if(count == 1)
            {
                if((!r.empty()) && ContainerContains(end, insn[0].mnemonic)) {
                    cs_free(insn, count);
                    break;
                }
                cs_insn k{};
                memcpy(&k, &insn[0], sizeof(cs_insn));
                r.emplace_back(k);
                address += k.size;
                p       += k.size;
                cs_free(insn, count);
            }else break;
        }
        cs_close(&handle);

        if(make)    // Save to static symbols
        {
            for(int i=0;i<staticSymbols.size();i++)
            {
                if(originAddress >= staticSymbols[i].address && originAddress < staticSymbols[i].address + staticSymbols[i].size)
                {
                    staticSymbols.erase(staticSymbols.begin() + i);
                    i--;
                }
            }

            Symbol sym{};
            sym.address = originAddress;
            sym.base = 0;
            sprintf(sym.name, "call_%lx", sym.address);
            for(const auto &k : r)
            {
                sym.size += k.size;
            }
            staticSymbols.emplace_back(sym);
        }

        return std::move(r);
    }

    bool GetMapEntire(uint64_t addr, MapEntire& ent)
    {
        for(int i=0;i<_map->Size();i++) // Read Text Data
        {
            auto item = _map->GetItem(i);
            if(item.startAddress == addr) {
                ent = item;
                return true;
            }
        }

        return false;
    }
private:
    bool entryBreak = true;

    int _process = -1;
    pthread_t _th = 0;
    std::string _path;
    std::string _argv;
    std::string _module;
    std::shared_ptr<MemoryMap> _map = nullptr;
    bool _temporaryStop = false;

    bool _trapped = false;

    void sendMessage(char id, void* param) const {
        DebugCommand msg{id, param};
        if (pipe != -1) {
            write(pipe, &msg, sizeof(DebugCommand));
        }
    }

    void debugHandler()
    {
        char str_buffer[128];
        std::vector<MapEntire> me;

        int fk = fork();
        if(fk == 0)
        {
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
                perror("ptrace");
                exit(1);
            }

            char env[255];
            strcpy(env, _path.c_str());
            env[_path.rfind('/') + 1] = 0;

            chdir(env);
            execl(_path.c_str(), _argv.c_str(), NULL);
            perror("execve");
            exit(1);
        }

        _process = fk;

        sprintf(str_buffer, "%s - [/proc/%d/]", _argv.c_str(), _process);
        sendMessage(MSG_TITLE, str_buffer);

        int status = 0;
        long err;
        char buffer[32];

        _ep = epoll_create1(0);
        auto ev1 = epoll_event{.events = EPOLLIN};
        ev1.data.fd = pipe;
        epoll_ctl(_ep, EPOLL_CTL_ADD, pipe, &ev1);
        sendMessage(MSG_STARTUP, nullptr);  // Notify Main Thread

        while(true)
        {
            // Handle User IO Message
            int n = epoll_wait(_ep, &ev1, 1, 1);
            if(n > 0)
            {
                auto sz = read(pipe, buffer, sizeof(DebugCommand));
                if(sz != sizeof(DebugCommand)) continue;

                auto msg = (DebugCommand*)buffer;
                switch (msg->id) {
                    case MSG_PAUSE:
                        kill(_process, SIGTRAP);
                        break;
                    case MSG_STOP:
                        kill(_process, SIGKILL);
                        sendMessage(MSG_STOP, nullptr);
                        return;
                    case MSG_RESTART:
                        kill(_process, SIGKILL);
                        sendMessage(MSG_RESTART, nullptr);
                        return;
                    case MSG_CONTINUE:
                        if(_trapped) {
                            TryContinue();
                            if(err == -1) perror("ptrace");
                            sendMessage(MSG_CONTINUE, nullptr);
                            _trapped = false;
                        }
                        break;
                    case MSG_STEPINTO:
                        if(_trapped) {
                            err = ptrace(PTRACE_SINGLESTEP, _process, NULL, NULL);
                            sendMessage(MSG_CONTINUE, nullptr);
                            _trapped = false;
                            break;
                        }
                    case MSG_STEPOVER:
                    {
                        auto ins = disassemblyFrom(_lastRip, 2, 0);

                        if(ins.size() < 2 || !std::string(ins[0].mnemonic).contains("call")){
                            err = ptrace(PTRACE_SINGLESTEP, _process, NULL, NULL);
                            sendMessage(MSG_CONTINUE, nullptr);
                            _trapped = false;
                            break;
                        }
                        if(!_breakPoints.contains(ins[1].address))
                            InsertBreakPoint(ins[1].address, true);

                        TryContinue();
                        sendMessage(MSG_CONTINUE, nullptr);
                        _trapped = false;
                        break;
                    }
                    case MSG_SWITCHSYMBOL:
                    {
                        auto b = reinterpret_cast<Symbol*>(msg->param);
                        auto ci = disassemblyFrom(b->base + b->address, 0, b->size);
                        auto ch = new std::vector<cs_insn>;
                        *ch = ci;

                        strcpy(currentSymbol.name, b->name);
                        currentSymbol.address = b->address;
                        currentSymbol.size = b->size;
                        currentSymbol.base = b->base;
                        // currentSymbol
                        sendMessage(MSG_ASM, ch);
                        sendMessage(MSG_CURRENTSYMBOL, nullptr);
                        sendMessage(MSG_SELECT, nullptr);
                        break;
                    }
                    case MSG_PARSE:
                    {
                        for(int i=0;i<_map->Size();i++) // Read Text Data
                        {
                            auto item = _map->GetItem(i);
                            me.emplace_back(item);
                            if(_lastRip >= item.startAddress && _lastRip < item.endAddress)
                            {
                                auto moduleBase = GetBaseAddress(_module);

                                auto ci = disassemblyFrom(_lastRip, 10000, item.endAddress - _lastRip, {"int3", "endbr64"}, true);
                                if(ci.empty()) break;

                                auto ch = new std::vector<cs_insn>;
                                *ch = ci;

                                sendMessage(MSG_ASM, ch);

                                sprintf(str_buffer, "%s - [/proc/%d/] - [%s] at %lx",
                                        _argv.c_str(), _process, _module.c_str(), moduleBase);

                                sprintf(currentSymbol.name, "call_%lx", _lastRip);
                                currentSymbol.address = _lastRip;
                                currentSymbol.size = item.endAddress - _lastRip;
                                currentSymbol.base = moduleBase;

                                symbols = GetSymbols(_module);
                                sendMessage(MSG_INSYM, nullptr);
                                sendMessage(MSG_TITLE, str_buffer);
                                sendMessage(MSG_SELECT, nullptr);
                                sendMessage(MSG_CURRENTSYMBOL, nullptr);
                                sendMessage(MSG_SYMBOLS, nullptr);
                            }
                        }
                        break;
                    }
                    case MSG_BREAK:
                    {
                        auto addr = (uint64_t)msg->param;
                        InsertBreakPoint(addr, false);
                        break;
                    }
                    case MSG_BREAKONCE:
                    {
                        auto addr = (uint64_t)msg->param;
                        InsertBreakPoint(addr, true);
                        break;
                    }
                    case MSG_DELBREAK:
                    {
                        auto addr = (uint64_t)msg->param;
                        DeleteBreakPoint(addr);
                        break;
                    }
                    case MSG_SWITCHMODULE:
                    {
                        _module = (char*)msg->param;
                        auto moduleBase = GetBaseAddress(_module);
                        symbols = GetSymbols(_module);
                        if(symbols.empty()) break;
                        currentSymbol = symbols[0];

                        sprintf(str_buffer, "%s - [/proc/%d/] - [%s] at %lx", _argv.c_str(), _process, _module.c_str(), moduleBase);

                        auto ci = disassemblyFrom(moduleBase + currentSymbol.address, 0, currentSymbol.size);
                        auto ch = new std::vector<cs_insn>;
                        *ch = ci;

                        sendMessage(MSG_ASM, ch);
                        sendMessage(MSG_TITLE, str_buffer);
                        sendMessage(MSG_SYMBOLS, nullptr);
                        sendMessage(MSG_CURRENTSYMBOL, nullptr);
                        sendMessage(MSG_SELECT, nullptr);

                        delete[](char*)msg->param;
                        break;
                    }
                    case MSG_GETBREAKS:
                    {
                        auto dst = new cs_insn[_breakPoints.size()];
                        int p = 0;

                        for(const auto &k : GetBreakpoints())
                        {
                            auto ins = disassemblyFrom(k.addr, 1, 0);
                            dst[p++] = ins[0];
                        }
                        sendMessage(MSG_GETBREAKS, dst);
                        break;
                    }
                    case MSG_CALLSTACK:
                    {
                        GetCallStack();
                        break;
                    }
                    default:
                        break;
                }
            }

            // Handle Debug Process Signal
            auto r = waitpid(_process, &status, WNOHANG);
            if(r == 0) continue;

            if(WIFEXITED(status) || WIFSIGNALED(status)) break;
            int signal_number = WSTOPSIG(status);

            switch (signal_number) {
                case SIGTRAP: {
                    _trapped = true;
                    _map = std::make_shared<MemoryMap>(_process);
                    regs = {};

                    me.clear();
                    ptrace(PTRACE_GETREGS, _process, NULL, &regs);


                    if(entryBreak)  // If this is the first time enter trap, insert int3 break point to Entry Point
                    {
                        entryBreak = false;
                        _trapped = false;
                        auto base = GetBaseAddress();
                        uint64_t entryPoint = base + GetEntryPoint();
                        InsertBreakPoint(entryPoint);

                        ptrace(PTRACE_CONT, _process, NULL, NULL);
                        break;
                    }

                    bool couldBeBp = true;
                    if(_needToRestore != 0)
                    {
                        RestoreBreakPoint(_needToRestore);
                        _needToRestore = 0;
                        couldBeBp = false;
                    }

                    if(_temporaryStop){
                        _trapped = false;
                        _temporaryStop = false;
                        ptrace(PTRACE_CONT, _process, NULL, NULL);
                        break;
                    }

                    if(_breakPoints.contains(regs.rip - 1) && couldBeBp)
                    {
                        // Reduce RIP by 1
                        regs.rip -= 1;
                        ptrace(PTRACE_SETREGS, _process, NULL, &regs);
                        // Restore origin data
                        if(_breakPoints[regs.rip].once)
                            DeleteBreakPoint(regs.rip);
                        else
                        {
                            DisableBreakPoint(regs.rip);
                            _needToRestore = regs.rip;
                        }
                    }

                    _lastRip = regs.rip;
                    bool updateModule = false;
                    bool ridSymbols = true;

                    for(int i=0;i<_map->Size();i++) // Read Text Data
                    {
                        auto item = _map->GetItem(i);
                        me.emplace_back(item);
                        if(regs.rip >= item.startAddress && regs.rip < item.endAddress)
                        {
                            if(_module != item.path) updateModule = true;

                            _module = item.path;
                            auto moduleBase = GetBaseAddress(_module);
                            symbols = GetSymbols(_module);

                            for(auto b : symbols)
                            {
                                // If Rip is between the start and the end of a module
                                if(regs.rip >= b.base + b.address && regs.rip < b.base + b.address + b.size)
                                {
                                    ridSymbols = false;
                                    if (currentSymbol.address == b.address) break;
                                    currentSymbol = b;

                                    auto ci = disassemblyFrom(moduleBase + b.address, 0, b.size);
                                    auto ch = new std::vector<cs_insn>;
                                    *ch = ci;

                                    sendMessage(MSG_ASM, ch);
                                    sendMessage(MSG_CURRENTSYMBOL, nullptr);
                                }
                            }
                            if(ridSymbols) {    // ridSymbols keeps true means RIP isn't in any Symbol
                                sprintf(str_buffer, "%s - [/proc/%d/] - [%s] at %lx (!Symbol table Escaping!)",
                                        _argv.c_str(), _process, _module.c_str(), moduleBase);
                                sendMessage(MSG_NONSYM, nullptr);

                                strcpy(currentSymbol.name, "[Out of Symbol Table]");
                                currentSymbol.address = _lastRip;
                                currentSymbol.size = item.endAddress - _lastRip;
                                currentSymbol.base = moduleBase;
                                sendMessage(MSG_CURRENTSYMBOL, nullptr);
                            }
                            else{
                                sprintf(str_buffer, "%s - [/proc/%d/] - [%s] at %lx", _argv.c_str(), _process, _module.c_str(), moduleBase);
                                sendMessage(MSG_INSYM, nullptr);
                            }
                            sendMessage(MSG_TITLE, str_buffer);
                        }
                    }

                    sendMessage(MSG_PAUSE, nullptr);
                    sendMessage(MSG_REG, &regs);
                    sendMessage(MSG_MEMORY, &me);
                    if(updateModule) sendMessage(MSG_SYMBOLS, nullptr);
                    sendMessage(MSG_SELECT, nullptr);
                    break;
                }
                case SIGTERM:
                    kill(_process, SIGKILL);
                    waitpid(_process, &status, 0);
                    _process = -1;
                    sendMessage(MSG_STOP, nullptr);
                    return;
                default:
                    break;
            }
        }

        sendMessage(MSG_STOP, nullptr);
    }

public:
    explicit Core(const std::string& f, const std::string& a)
    {
        _path = f;
        _argv = a;

        auto lambda = [](void *arg) {
            Core* instance = static_cast<Core*>(arg);
            instance->debugHandler();
            return (void*)nullptr;
        };

        pthread_create(&_th, nullptr, lambda, this);
    }

    ~Core()
    {
        if(_process > 0)
        {
            pthread_join(_th, nullptr);
            // delete[] codeData;
            close(_ep);
        }
    }

    bool Status() const
    {
        return _trapped;
    }



    std::optional<Symbol> GetSymbolAt(uint64_t address, std::string &mod)
    {
        auto _m = _map->GetModules();
        for(const auto &k : _m)
        {
            if(address >= k.startAddress && address < k.endAddress)
            {
                mod = k.path;
                for(const auto &l : GetSymbols(k.path))
                {
                    if(address >= l.address + l.base && address < l.address + l.size + l.base)
                    {
                        return l;
                    }
                }
            }
        }

        return std::nullopt;
    }

    void GetCallStack()
    {
        std::vector<std::pair<uint64_t, uint64_t>> callPoints;
        auto r = new std::stack<CallstackStruct>;
        uint64_t cbp = regs.rbp;

        callPoints.emplace_back(regs.rip, cbp);

        while(cbp)
        {
            callPoints.emplace_back(ptrace(PTRACE_PEEKDATA, _process, cbp + 8, NULL), ptrace(PTRACE_PEEKDATA, _process, cbp, NULL));
            cbp = ptrace(PTRACE_PEEKDATA, _process, cbp, NULL);
        }
        int cc = 0;
        for(const auto &k : callPoints)
        {
            std::string mod;
            auto s = GetSymbolAt(k.first, mod);

            Symbol s2{};
            strcpy(s2.name, "<???>");
            if(s.has_value()) s2 = s.value();

            CallstackStruct e{};
            e.callPoint = k.first;
            sprintf(e.module, "<%s>", mod.empty() ? "???" : mod.c_str());
            e.symbol = s2;
            e.stackBase = k.second;
            e.depth = cc++;

            r->emplace(e);
        }
        CallstackStruct e{};
        e.depth = _process;
        r->emplace(e);
        sendMessage(MSG_CALLSTACK, r);
    }
};

#endif