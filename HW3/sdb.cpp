#include "dbg.hpp"

using namespace std;

Elf64_Ehdr elf_header;
Elf64_Shdr text_shdr;

string sdb_unload_loop() {
    bool isload = false;
    string line;
    vector<string> tokens;
    while (!isload) {
        cout << "(sdb) ";
        getline(cin, line);
        tokens = split(line, ' ');
        if (tokens[0] == "load" && tokens.size() == 2) {
            isload = true;
        } else {
            cout << "** please load a program first.\n";
        }
    }
    return tokens[1];
}

void read_elf(string prog) {
    FILE *fp = fopen(prog.c_str(), "rb");
    if (fp == NULL) errquit("fopen");
    fread(&elf_header, 1, sizeof(Elf64_Ehdr), fp);
    if (elf_header.e_ident[EI_MAG0] != ELFMAG0 || elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header.e_ident[EI_MAG2] != ELFMAG2 || elf_header.e_ident[EI_MAG3] != ELFMAG3) {
        errquit("not an ELF file");
    }
    Elf64_Shdr str_table_shdr, shdr;
    char str_table[500];
    bzero(str_table, sizeof(str_table));
    int str_shdr_off = elf_header.e_shstrndx * sizeof(Elf64_Shdr) + elf_header.e_shoff;
    fseek(fp, str_shdr_off, SEEK_SET);
    fread(&str_table_shdr, sizeof(Elf64_Shdr), 1, fp);
    fseek(fp, str_table_shdr.sh_offset, SEEK_SET);
    fread(str_table, sizeof(char), str_table_shdr.sh_size, fp);
    fseek(fp, elf_header.e_shoff, SEEK_SET);
    for (int i = 0; i < elf_header.e_shnum; i++) {
        fread(&shdr, sizeof(Elf64_Shdr), 1, fp);
        if (strcmp((str_table + shdr.sh_name), ".text") == 0) {
            text_shdr = shdr;
            break;
        }
    }
    fclose(fp);
}

void sdb(string prog) {
    read_elf(prog);
    pid_t pid;
    if ((pid = fork()) < 0) errquit("fork");
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
        execl(prog.c_str(), prog.c_str(), NULL);
        errquit("execl");
    } else {
        dbg debugger(pid, prog, elf_header, text_shdr);
        debugger.run();
    }
}

int main(int argc, char *argv[]) {
    string prog;
    if (argc == 1) {
        prog = sdb_unload_loop();
        sdb(prog);
    } else if (argc == 2) {
        prog = argv[1];
        sdb(prog);
    } else {
        cerr << "Usage: ./sdb [executable]\n";
        return -1;
    }

    return 0;
}