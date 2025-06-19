#include "dbg.hpp"

using namespace std;

void errquit(const char *msg) {
    perror(msg);
    exit(-1);
}

vector<string> split(string line, char delim) {
    vector<string> tokens;
    string token;
    stringstream ss(line);
    while (getline(ss, token, delim)) {
        if (token == "") continue;
        tokens.push_back(token);
    }
    return tokens;
}

void dbg::run() {
    if (waitpid(pid, &status, 0) < 0) errquit("wait");
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD);
    print_load_msg();
    loop();
}

void dbg::loop() {
    string line;
    vector<string> tokens;
    while (WIFSTOPPED(status)) {
        cout << "(sdb) ";
        getline(cin, line);
        if (line == "") continue;
        tokens = split(line, ' ');
        if (tokens[0] == "si") {
            step_instruction();
        } else if (tokens[0] == "cont") {
            cont();
        } else if (tokens[0] == "info" && tokens[1] == "reg") {
            info_reg();
        } else if (tokens[0] == "break") {
            breakpoint(stoull(tokens[1], nullptr, 16));
        } else if (tokens[0] == "info" && tokens[1] == "break") {
            info_break();
        } else if (tokens[0] == "delete") {
            delete_break(stoi(tokens[1]));
        } else if (tokens[0] == "patch") {
            patch(stoull(tokens[1], nullptr, 16), stoul(tokens[2], nullptr, 16), stoi(tokens[3]));
        } else if (tokens[0] == "syscall") {
            syscall();
        }
    }
    return;
}

void dbg::print_load_msg() {
    printf("** program '%s' loaded. entry point 0x%llx.\n", name.c_str(), entry_point);
    disassemble(5, entry_point);
}

void dbg::disassemble(int instr_num, unsigned long long start) {
    csh handle;
    cs_insn *insn;
    int count;
    int i;
    char buf[128] = {0};
    char bytes[128] = "";
    unsigned long long ptr = start;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        errquit("cs_open() failed");
    }

    for (ptr = start; ptr < start + sizeof(buf); ptr += 8) {
        long long peek;
        errno = 0;
        peek = ptrace(PTRACE_PEEKTEXT, pid, ptr, NULL);
        if (errno != 0) break;
        memcpy(&buf[ptr - start], &peek, 8);
    }

    if ((count = cs_disasm(handle, (uint8_t*) buf, start - ptr + 8, start, 0, &insn)) > 0) {
        for (i = 0; i < instr_num; i++) {
            for (int j = 0; j < insn[i].size; j++) {
                snprintf(&bytes[j*3], 4, "%2.2x ", insn[i].bytes[j]);
            }
            if (insn[i].address == text_shdr.sh_addr + text_shdr.sh_size) {
                cout << "** the address is out of the range of the text section.\n";
                break;
            }
            printf("\t%8lx: %-32s\t%-10s\t%s\n", insn[i].address, bytes, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    }

    cs_close(&handle);
}

void dbg::step_instruction() {
    bool isrun = false;
    if (isbreak) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) errquit("step");
        if (waitpid(pid, &status, 0) < 0) errquit("wait");
        isrun = true;
    }
    set_all_bp();
    if (!isrun) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) errquit("step");
        if (waitpid(pid, &status, 0) < 0) errquit("wait");
    }
    if (WIFEXITED(status)) {
        cout << "** the target program terminated.\n";
    } else {
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) errquit("getregs");
        restore_all_bp();
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            for (auto b : bp) {
                if (b.first == regs.rip) {
                    cout << "** hit a breakpoint at 0x" << hex << regs.rip << ".\n";
                    disassemble(5, regs.rip);
                    return;
                }
            }
        }
        disassemble(5, regs.rip);
    }
}

void dbg::cont() {
    if (isbreak) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) errquit("step");
        if (waitpid(pid, &status, 0) < 0) errquit("wait");
    }
    set_all_bp();
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) errquit("cont");
    if (waitpid(pid, &status, 0) < 0) errquit("wait");
    if (WIFEXITED(status)) {
        cout << "** the target program terminated.\n";
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) errquit("getregs");
        restore_all_bp();
        for (auto b : bp) {
            if (b.first == regs.rip - 1) {
                cout << "** hit a breakpoint at 0x" << hex << b.first << ".\n";
                regs.rip = regs.rip - 1;
                if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0) errquit("setregs");
                disassemble(5, b.first);
                isbreak = true;
                return;
            }
        }
    }
}

void dbg::info_reg() {
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
        printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
        printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
        printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8 );
        printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9 , regs.r10, regs.r11);
        printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
        printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
    }
}

void dbg::set_all_bp() {
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) errquit("getregs");
    for (auto b : bp) {
        if (b.first == regs.rip && !isbreak) {
            long long code = ptrace(PTRACE_PEEKTEXT, pid, b.first, NULL);
            if ((code & 0xff) == 0xcc) {
                if (ptrace(PTRACE_POKETEXT, pid, b.first, (code & 0xffffffffffffff00) | b.second) != 0) errquit("restore breakpoint");
            }
            continue;
        }
        breakpoint(b.first);
    }
    isbreak = false;
}

void dbg::restore_all_bp() {
    for (auto b : bp) {
        long long code = ptrace(PTRACE_PEEKTEXT, pid, b.first, NULL);
        if ((code & 0xff) == 0xcc) {
            if (ptrace(PTRACE_POKETEXT, pid, b.first, (code & 0xffffffffffffff00) | b.second) != 0) errquit("restore breakpoint");
        }
    }
}

void dbg::breakpoint(unsigned long long addr) {
    long long code = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if ((code & 0xff) != 0xcc) {
        if (ptrace(PTRACE_POKETEXT, pid, addr, (code & 0xffffffffffffff00) | 0xcc) != 0) errquit("breakpoint");
        if (bp.find(addr) == bp.end()) {
            bp_index[bp_num] = addr;
            bp_num++;
            cout << "** set a breakpoint at 0x" << hex << addr << ".\n";
        }
        bp[addr] = code & 0xff;
    }
}

void dbg::info_break() {
    if (bp_index.empty()) {
        cout << "** no breakpoints.\n";
    } else {
        cout << "Num\tAddress\n";
        for (auto b : bp_index) {
            cout << b.first << "\t0x" << hex << b.second << "\n";
        }
    }
}

void dbg::delete_break(int id) {
    if (bp_index.find(id) != bp_index.end()) {
        long long code = ptrace(PTRACE_PEEKTEXT, pid, bp_index[id], NULL);
        if ((code & 0xff) == 0xcc) {
            if (ptrace(PTRACE_POKETEXT, pid, bp_index[id], (code & 0xffffffffffffff00) | bp[bp_index[id]]) != 0) errquit("delete breakpoint");
        }
        bp.erase(bp_index[id]);
        bp_index.erase(id);
        cout << "** delete breakpoint " << id << ".\n";
    } else {
        cout << "** breakpoint " << id << " does not exist.\n";
    }
}

void dbg::patch(unsigned long long addr, unsigned long val, int len) {
    long long code = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    unsigned long long mask;
    switch (len) {
    case 1:
        mask = 0xffffffffffffff00;
        break;
    case 2:
        mask = 0xffffffffffff0000;
        break;
    case 4:
        mask = 0xffffffff00000000;
        break;
    case 8:
        mask = 0x0000000000000000;
        break;
    default:
        break;
    }
    if (ptrace(PTRACE_POKETEXT, pid, addr, (code & mask) | val) != 0) errquit("patch");
    cout << "** patch memory at address 0x" << hex << addr << ".\n";
}

void dbg::syscall() {
    if (isbreak) {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0) errquit("step");
        if (waitpid(pid, &status, 0) < 0) errquit("wait");
    }
    set_all_bp();
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) errquit("syscall");
    if (waitpid(pid, &status, 0) < 0) errquit("wait");
    if (WIFEXITED(status)) {
        cout << "** the target program terminated.\n";
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) errquit("getregs");
        restore_all_bp();
        for (auto b : bp) {
            if (b.first == regs.rip - 1) {
                cout << "** hit a breakpoint at 0x" << hex << b.first << ".\n";
                regs.rip = regs.rip - 1;
                if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0) errquit("setregs");
                disassemble(5, b.first);
                isbreak = true;
                return;
            }
        }
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) errquit("getregs");
        if (enter) {
            cout << "** enter a syscall(" << dec << regs.orig_rax << ") at 0x" << hex << regs.rip - 2 << ".\n";
        } else {
            cout << "** leave a syscall(" << dec << regs.orig_rax << ") = " << dec << regs.rax << " at 0x" << hex << regs.rip - 2 << ".\n";
        }
        disassemble(5, regs.rip - 2);
        enter ^= 0x01;
    }
}
