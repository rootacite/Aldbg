
#include <gtkmm.h>
#include <iostream>
#include <glibmm.h>
#include <memory>

#include "interface/log/LogView.hpp"
#include "interface/cpu/CPUView.hpp"

#include "../core/Core.hpp"
#include "interface/cpu/RegView.hpp"
#include "interface/cpu/SymbolMenu.hpp"
#include "interface/memory/MemoryView.hpp"
#include "interface/callstack/CallstackView.hpp"
#include "interface/editor/EditorView.hpp"

class HomeWindow : public Gtk::Window
{
public:
    void sendMessage(char id, void* param) const
    {
        DebugCommand msg{id, param};
        if(sock_pair[0] != -1)
        {
            write(sock_pair[0], &msg, sizeof(DebugCommand));
        }
    }
protected:
    int sock_pair[2]{};

    Glib::RefPtr<Gtk::Builder> _refBuilder;
    Glib::RefPtr<Gtk::Application> _app         = nullptr;

    std::shared_ptr<Core> _core = nullptr;

    pthread_t _th = 0;

    std::string _lastPath = "";
    std::string _lastArgv = "";

    char buffer[32] = {0};
    int ep = -1;
    epoll_event ev1 {};

    std::vector<cs_insn>* pInsn = nullptr;

public: // Elements
    Glib::RefPtr<CPUView> codeView              = nullptr;
    Glib::RefPtr<LogView> logView               = nullptr;
    Glib::RefPtr<Gtk::Button> bAttach           = nullptr;
    Glib::RefPtr<Gtk::Dialog> dialogAttach      = nullptr;
    Glib::RefPtr<Gtk::Button> dCancel           = nullptr;
    Glib::RefPtr<Gtk::Button> dAttach           = nullptr;
    Glib::RefPtr<Gtk::Button> bStop             = nullptr;
    Glib::RefPtr<Gtk::Button> bCont             = nullptr;
    Glib::RefPtr<Gtk::Button> bSuspend          = nullptr;
    Glib::RefPtr<Gtk::Box> debugBox             = nullptr;
    Glib::RefPtr<Gtk::TextView> tExecutable     = nullptr;
    Glib::RefPtr<Gtk::TextView> tArg            = nullptr;
    Glib::RefPtr<Gtk::ScrolledWindow> logScroll = nullptr;
    Glib::RefPtr<Gtk::HeaderBar> HeaderBar      = nullptr;
    Glib::RefPtr<Gtk::Button> bRestart          = nullptr;
    Glib::RefPtr<RegView>     regView           = nullptr;
    Glib::RefPtr<Gtk::Label>  windowTitle       = nullptr;
    Glib::RefPtr<Gtk::Button> bStepinto         = nullptr;
    Glib::RefPtr<MemoryView> memory             = nullptr;
    Glib::RefPtr<Gtk::Popover> popover1         = nullptr;
    Glib::RefPtr<Gtk::Box> popover1Box          = nullptr;
    Glib::RefPtr<Gtk::Label> currentSymbol      = nullptr;
    Glib::RefPtr<Gtk::Button> bStepover         = nullptr;
    Glib::RefPtr<SymbolMenu> mSymbols           = nullptr;
    Glib::RefPtr<Gtk::Button> bTryParse         = nullptr;
    Glib::RefPtr<CPUView> breakpoints           = nullptr;
    Glib::RefPtr<Gtk::Stack> stack              = nullptr;
    Glib::RefPtr<CallstackView> callstack       = nullptr;
    Glib::RefPtr<Gtk::Button> bGoto             = nullptr;
    Glib::RefPtr<EditorView> editor             = nullptr;
    Glib::RefPtr<Gtk::Button> bMemPush             = nullptr;
    Glib::RefPtr<Gtk::Button> bMemPull             = nullptr;
    Glib::RefPtr<Gtk::Button> bMemJump             = nullptr;

public:

    HomeWindow(BaseObjectType *cobject, const Glib::RefPtr<Gtk::Builder> &refBuilder, const Glib::RefPtr<Gtk::Application>& app) :
    Gtk::Window(cobject), _refBuilder(refBuilder), _app(app),
    codeView(_refBuilder->get_widget_derived<CPUView>(_refBuilder, "code")),
    regView(_refBuilder->get_widget_derived<RegView>(_refBuilder, "reg")),
    logScroll(refBuilder->get_widget<Gtk::ScrolledWindow>("logScroll")),
    bAttach(refBuilder->get_widget<Gtk::Button>("bAttach")),
    dialogAttach(refBuilder->get_widget<Gtk::Dialog>("dialogAttach")),
    dCancel(refBuilder->get_widget<Gtk::Button>("dCancel")),
    dAttach(refBuilder->get_widget<Gtk::Button>("dAttach")),
    bStop(refBuilder->get_widget<Gtk::Button>("bStop")),
    debugBox(refBuilder->get_widget<Gtk::Box>("debugBox")),
    tExecutable(refBuilder->get_widget<Gtk::TextView>("tExecutable")),
    tArg(refBuilder->get_widget<Gtk::TextView>("tArg")),
    logView(_refBuilder->get_widget_derived<LogView>(_refBuilder, "log")),
    bCont(refBuilder->get_widget<Gtk::Button>("bCont")),
    bSuspend(refBuilder->get_widget<Gtk::Button>("bSuspend")),
    HeaderBar(refBuilder->get_widget<Gtk::HeaderBar>("HeaderBar")),
    bRestart(refBuilder->get_widget<Gtk::Button>("bRestart")),
    windowTitle(refBuilder->get_widget<Gtk::Label>("windowTitle")),
    bStepinto(refBuilder->get_widget<Gtk::Button>("bStepinto")),
    memory(_refBuilder->get_widget_derived<MemoryView>(_refBuilder, "memory")),
    popover1(refBuilder->get_widget<Gtk::Popover>("popover1")),
    popover1Box(refBuilder->get_widget<Gtk::Box>("popover1Box")),
    currentSymbol(refBuilder->get_widget<Gtk::Label>("currentSymbol")),
    bStepover(refBuilder->get_widget<Gtk::Button>("bStepover")),
    mSymbols(refBuilder->get_widget_derived<SymbolMenu>(_refBuilder, "mSymbols")),
    bTryParse(refBuilder->get_widget<Gtk::Button>("bTryParse")),
    breakpoints(_refBuilder->get_widget_derived<CPUView>(_refBuilder, "breakpoints")),
    stack(refBuilder->get_widget<Gtk::Stack>("stack")),
    callstack(_refBuilder->get_widget_derived<CallstackView>(_refBuilder, "callstack")),
    bGoto(refBuilder->get_widget<Gtk::Button>("bGoto")),
    editor(_refBuilder->get_widget_derived<EditorView>(_refBuilder, "editor")),
    bMemPush(refBuilder->get_widget<Gtk::Button>("bMemPush")),
    bMemPull(refBuilder->get_widget<Gtk::Button>("bMemPull")),
    bMemJump(refBuilder->get_widget<Gtk::Button>("bMemJump"))
    {
        socketpair(AF_UNIX, SOCK_STREAM, 0, sock_pair);
        ep = epoll_create1(0);

        ev1 = epoll_event{.events = EPOLLIN};
        ev1.data.fd = sock_pair[0];
        epoll_ctl(ep, EPOLL_CTL_ADD, sock_pair[0], &ev1);
        bTryParse->hide();
        this->add_tick_callback([this](const Glib::RefPtr<Gdk::FrameClock>& c){
            int n = epoll_wait(ep, &ev1, 1, 0);
            if(n > 0)
            {
                auto sz = read(sock_pair[0], buffer, sizeof(DebugCommand));
                if(sz != sizeof(DebugCommand)) return true;

                auto msg = (DebugCommand*)buffer;
                switch (msg->id) {
                    case MSG_PAUSE:
                        UpdateUI(1, BTN_CONT | BTN_STOP | BTN_STI);
                        break;
                    case MSG_STOP:
                        _core = nullptr;
                        UpdateUI(0, BTN_ATTACH);
                        break;
                    case MSG_CONTINUE:
                        UpdateUI(2, BTN_INT | BTN_STOP);
                        break;
                    case MSG_STARTUP:
                        UpdateUI(0, BTN_INT | BTN_STOP);
                        break;
                    case MSG_REG:{
                        auto reg = reinterpret_cast<user_regs_struct*>(msg->param);
                        UpdateUI(0, 0, reg);    // The first two parameters do not take effect when reg isn't empty
                        codeView->rip = reg->rip;
                        break;
                    }
                    case MSG_QUIT:
                        return false;
                    case MSG_LOG:
                        logView->add_log_data((char*)msg->param);
                        delete[] (char*)msg->param;
                        break;
                    case MSG_TITLE:
                        windowTitle->set_text((char*)msg->param);
                        break;
                    case MSG_MEMORY:{
                        auto pList = reinterpret_cast<std::vector<MapEntire>*>(msg->param);
                        memory->set_data(*pList);
                        break;
                    }
                    case MSG_ASM:{
                        delete pInsn;
                        pInsn = reinterpret_cast<std::vector<cs_insn>*>(msg->param);
                        codeView->setData(*pInsn);
                        break;
                    }
                    case MSG_SELECT:
                        codeView->Select();
                        break;
                    case MSG_CURRENTSYMBOL:
                        currentSymbol->set_text(_core->currentSymbol.name);
                        break;
                    case MSG_RESTART:
                        _core = std::make_shared<Core>(_lastPath, _lastArgv);
                        _core->pipe = sock_pair[1];
                        _core->remotePipe = sock_pair[0];
                        codeView->core = _core;
                        breakpoints->core = _core;

                        bAttach->set_sensitive(false);
                        logView->clear();
                        break;
                    case MSG_SYMBOLS:
                        mSymbols->UpdateList(_core->symbols);
                        break;
                    case MSG_NONSYM:
                        bTryParse->show();
                        break;
                    case MSG_INSYM:
                        bTryParse->hide();
                        break;
                    case MSG_GETBREAKS:
                    {
                        breakpoints->clear();
                        auto insn = reinterpret_cast<cs_insn*>(msg->param);
                        auto count = _core->GetBreakpoints().size();

                        for (size_t i = 0; i < count; i++) {
                            char cmdAddr[32], insByte[32];
                            std::string bytes, cmdStr;
                            for(int j = 0;j<insn[i].size;j++)
                            {
                                sprintf(insByte, "%2x", insn[i].bytes[j]);
                                bytes += insByte;
                            }
                            sprintf(cmdAddr, "%16lx", insn[i].address);
                            cmdStr = insn[i].mnemonic;
                            cmdStr += " ";
                            cmdStr += insn[i].op_str;

                            breakpoints->add_row(cmdAddr, bytes, cmdStr, _core->ContainsBreakPoint(insn[i].address));
                        }
                        delete[] insn;
                        break;
                    }
                    case MSG_CALLSTACK:
                    {
                        auto *p = (std::stack<CallstackStruct>*)msg->param;

                        callstack->clear();
                        while(!p->empty())
                        {
                            std::string name = "Thread: ";
                            std::vector<CallstackItem> g;
                            name += std::to_string(p->top().depth);
                            p->pop();

                            int depth = INT_MAX;
                            do
                            {
                                char strBuf[512];
                                depth = p->top().depth;
                                CallstackItem i{};
                                i.depth = std::to_string(depth);

                                sprintf(strBuf, "%lX", p->top().callPoint);
                                i.callPoint = strBuf;

                                sprintf(strBuf, "%lX", p->top().stackBase);
                                i.stackBase = strBuf;

                                i.symbol = p->top().symbol.name;
                                i.module = p->top().module;
                                g.emplace_back(i);
                                p->pop();
                            }while(depth);

                            callstack->append_group(name, g);
                        }
                        delete p;
                        break;
                    }
                    default:
                        break;
                }
            }
            return true;
        });
        mSymbols->popoverBox = popover1Box;
        mSymbols->childLabel = currentSymbol;
        mSymbols->port = sock_pair[0];

        _app->signal_activate().connect([this](){
            _app->add_window(*this);
            this->show();
        });

        codeView->add_css_class("code_view");

        dialogAttach->set_hide_on_close(true);

        bAttach->signal_clicked().connect([this](){
            dialogAttach->set_transient_for(*this);
            dialogAttach->show();
        });

        dCancel->signal_clicked().connect([this](){
            dialogAttach->close();
        });

        dAttach->signal_clicked().connect([this](){
            auto s = tExecutable->get_buffer()->get_text();
            std::size_t pos = s.rfind('/');
            std::string filename = (pos != std::string::npos) ? s.substr(pos + 1) : s;

            dialogAttach->close();
            _lastPath = s;
            _lastArgv = filename;

            _core = std::make_shared<Core>(s, filename);
            _core->pipe = sock_pair[1];
            _core->remotePipe = sock_pair[0];
            codeView->core = _core;
            breakpoints->core = _core;

            bAttach->set_sensitive(false);
            logView->clear();
        });

        bStop->signal_clicked().connect([this](){
            if(_core)
            {
                codeView->clear();
                sendMessage(MSG_STOP, nullptr);
                _core = nullptr;
                codeView->core = nullptr;
                breakpoints->core = nullptr;
            }
        });

        bSuspend->signal_clicked().connect([this](){
            sendMessage(MSG_PAUSE, nullptr);
        });

        bCont->signal_clicked().connect([this](){
            sendMessage(MSG_CONTINUE, nullptr);
        });

        bStepinto->signal_clicked().connect([this](){
            sendMessage(MSG_STEPINTO, nullptr);
        });

        bRestart->signal_clicked().connect([this](){
            if(!_lastPath.empty())
            {
                if(!_core)
                {
                    _core = std::make_shared<Core>(_lastPath, _lastArgv);
                    _core->pipe = sock_pair[1];
                    _core->remotePipe = sock_pair[0];
                    codeView->core = _core;
                    breakpoints->core = _core;

                    bAttach->set_sensitive(false);
                    logView->clear();
                    return;
                }
                sendMessage(MSG_RESTART, nullptr);
                _core = nullptr;
                codeView->core = nullptr;
                breakpoints->core = nullptr;

                printf("%s\n", "Pending to Restart");
            }
        });

        bStepover->signal_clicked().connect([this](){
            sendMessage(MSG_STEPOVER, nullptr);
        });
        bGoto->signal_clicked().connect([this](){
            auto i = codeView->GetSelected();
            _core->queueMessage(MSG_BREAKONCE, (void*)i);
            sendMessage(MSG_CONTINUE, nullptr);
        });

        bTryParse->signal_clicked().connect([this](){
            sendMessage(MSG_PARSE, nullptr);
        });

        memory->signal_row_activated().connect([this](const Gtk::TreeModel::Path& p, Gtk::TreeViewColumn* c){
            auto iter = memory->get_model()->get_iter(p);
            if(iter)
            {
                Glib::ustring addr;
                (*iter).get_value(0, addr);
                printf("%s\n", addr.c_str());

                MapEntire me;
                _core->GetMapEntire(std::stoull(addr, nullptr, 16), me);

                if(me.access & EXECUTE)
                {
                    auto buf = new char[512];
                    strcpy(buf, me.path);
                    sendMessage(MSG_SWITCHMODULE, buf);
                }
            }
        });

        stack->property_visible_child().signal_changed().connect([this](){
            auto name = stack->get_visible_child_name();
            if(name == "Breakpoints" && _core != nullptr)
            {
                if(_core)
                    sendMessage(MSG_GETBREAKS, nullptr);
            }else if(name == "CPU" && _core != nullptr)
            {
                if(pInsn)
                    codeView->setData(*pInsn);
                codeView->Select();
            }else if(name == "Call Stack" && _core != nullptr)
            {
                if(_core)
                    sendMessage(MSG_CALLSTACK, nullptr);
            }

        });

        UpdateUI(0, BTN_ATTACH);
    }

    static Glib::RefPtr<HomeWindow> create()
    {
        auto app = Gtk::Application::create("acite.aldbg.app");
        auto refBuilder = Gtk::Builder::create();
        refBuilder->add_from_file("../aldbg.ui");
        auto home = Gtk::Builder::get_widget_derived<HomeWindow>(refBuilder, "MainWindow", app);

        if (!home) {
            std::cerr << "No \"MainWindow\" object in main-window.ui" << std::endl;
            return nullptr;
        }

        auto css_provider = Gtk::CssProvider::create();
        css_provider->load_from_path("../interface/style.css");

        // 将 CSS 提供程序应用到屏幕
        Gtk::StyleContext::add_provider_for_display(Gdk::Display::get_default(), css_provider, GTK_STYLE_PROVIDER_PRIORITY_USER);

        return Glib::make_refptr_for_instance<HomeWindow>(home);
    }

    enum ButtonMask
    {
        BTN_ATTACH  = 0x01,
        BTN_STOP    = 0x02,
        BTN_CONT    = 0x04,
        BTN_INT     = 0x08,
        BTN_STI     = 0x10
    };

    void UpdateUI(int status, uint64_t buttons, user_regs_struct* reg = nullptr)
    {
        if(reg)
        {
            regView->clear();
            regView->add_data("rax", reg->rax);
            regView->add_data("rbx", reg->rbx);
            regView->add_data("rcx", reg->rcx);
            regView->add_data("rdx", reg->rdx);
            regView->add_data("rbp", reg->rbp);
            regView->add_data("rsp", reg->rsp);
            regView->add_data("pc", reg->rip);
            return;
        }
        switch(status)
        {
            case 0:
                HeaderBar->remove_css_class("cont");
                HeaderBar->remove_css_class("trap");
                break;
            case 1:
                HeaderBar->remove_css_class("cont");
                HeaderBar->add_css_class("trap");
                break;
            case 2:
                HeaderBar->add_css_class("cont");
                HeaderBar->remove_css_class("trap");
                break;
            default:
                break;
        }

        bSuspend->set_sensitive(buttons & BTN_INT);
        bCont->set_sensitive(buttons & BTN_CONT);
        bAttach->set_sensitive(buttons & BTN_ATTACH);
        bStop->set_sensitive(buttons & BTN_STOP);
        bStepinto->set_sensitive(buttons & BTN_STI);
        bStepover->set_sensitive(buttons & BTN_STI);
        mSymbols->set_sensitive(buttons & BTN_STI);
        bGoto->set_sensitive(buttons & BTN_STI);

        bMemJump->set_sensitive(buttons & BTN_STI);
        bMemPull->set_sensitive(buttons & BTN_STI);
        bMemPush->set_sensitive(buttons & BTN_STI);
    }

    int loop()
    {
        return _app->run();
    }
};