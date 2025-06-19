#ifndef DBG_HPP
#define DBG_HPP

#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <elf.h>

#include <capstone/capstone.h>

void errquit(const char *msg);

std::vector<std::string> split(std::string line, char delim);

class dbg {
public:
    dbg (pid_t pid, std::string name, Elf64_Ehdr elf_header, Elf64_Shdr text_shdr) :
        pid(pid), name(name), elf_header(elf_header), text_shdr(text_shdr) {}
    
    void run();
    void loop();
    void print_load_msg();
    void disassemble(int count, unsigned long long start);
    void step_instruction();
    void cont();
    void info_reg();
    void set_all_bp();
    void restore_all_bp();
    void breakpoint(unsigned long long addr);
    void info_break();
    void delete_break(int id);
    void patch(unsigned long long addr, unsigned long val, int len);
    void syscall();

    ~dbg() {}

private:
    pid_t pid;
    std::string name;
    int status;
    struct user_regs_struct regs;
    Elf64_Ehdr elf_header;
    Elf64_Shdr text_shdr;
    unsigned long long entry_point = elf_header.e_entry;
    std::map<unsigned long long, long long> bp;
    std::map<int, unsigned long long> bp_index;
    int bp_num = 0;
    int enter = 0x01;
    bool isbreak = false;
};

#endif