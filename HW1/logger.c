#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *shared_object = "./logger.so";
    char *output_file = "";
    int has_output_file = 0;
    char **command_args = NULL;
    for(int i = 0; i < argc; i++) {
        if (i == 1 && strcmp(argv[i], "config.txt") != 0) {
            fprintf(stderr, "Missing command: config.txt\n");
            fprintf(stderr, "Usage: ./logger config.txt [-o file] [-p sopath] command [arg1 arg2 ...]\n");
            return 1;
        }

        if (i >= 2 && argv[i][0] != '-') {
            command_args = argv + i;
            setenv("LD_PRELOAD", shared_object, 1);
            if (has_output_file == 1) setenv("OUTPUT_FILE", output_file, 1);
            setenv("CONFIG_FILE", argv[1], 1);
            execvp(command_args[0], command_args);
            return 0;
        }

        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'p':
                    shared_object = argv[i+1];
                    i++;
                    break;
                case 'o':
                    output_file = argv[i+1];
                    has_output_file = 1;
                    i++;
                    break;
                default:
                    fprintf(stderr, "Unknown option: %s\n", argv[i]);
                    fprintf(stderr, "Usage: ./logger config.txt [-o file] [-p sopath] command [arg1 arg2 ...]\n");
                    return 1;
            }
        }
    }
    return 0;
}