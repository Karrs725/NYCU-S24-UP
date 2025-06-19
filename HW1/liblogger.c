#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <dlfcn.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <fnmatch.h>

char real_path[PATH_MAX];

struct Blacklist {
    struct Blacklist *next;
    char *str;
};

struct Blacklist *getblacklist(char *function_name) {
    char *config_file = getenv("CONFIG_FILE");
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    FILE *(*fop)(const char *, const char *) = dlsym(handle, "fopen");

    FILE *f_conf = fop(config_file, "r+");
    char *str = NULL;
    size_t len = 0;
    ssize_t nread;
    int flag = 0;
    struct Blacklist *openblacklist = NULL;
    struct Blacklist *readblacklist = NULL;
    struct Blacklist *writeblacklist = NULL;
    struct Blacklist *connectblacklist = NULL;
    struct Blacklist *getaddrinfoblacklist = NULL;

    while ((nread = getline(&str, &len, f_conf)) != -1) {
        if (str[nread - 1] == '\n') str[nread - 1] = '\0';
        if (strcmp(str, "BEGIN open-blacklist") == 0) flag = 1;
        else if (strcmp(str, "END open-blacklist") == 0) flag = 0;
        else if (strcmp(str, "BEGIN read-blacklist") == 0) flag = 2;
        else if (strcmp(str, "END read-blacklist") == 0)  flag = 0;
        else if (strcmp(str, "BEGIN write-blacklist") == 0) flag = 3;
        else if (strcmp(str, "END write-blacklist") == 0) flag = 0;
        else if (strcmp(str, "BEGIN connect-blacklist") == 0) flag = 4;
        else if (strcmp(str, "END connect-blacklist") == 0) flag = 0;
        else if (strcmp(str, "BEGIN getaddrinfo-blacklist") == 0) flag = 5;
        else if (strcmp(str, "END getaddrinfo-blacklist") == 0) flag = 0;
        else if (flag == 1) {
            struct Blacklist *tmp = openblacklist;
            openblacklist = (struct Blacklist *)malloc(sizeof(struct Blacklist));
            openblacklist->next = tmp;
            openblacklist->str = (char *)malloc(PATH_MAX * sizeof(char));
            strcpy(openblacklist->str, str);
        }
        else if (flag == 2) {
            readblacklist = (struct Blacklist *)malloc(sizeof(struct Blacklist));
            readblacklist->next = NULL;
            readblacklist->str = (char *)malloc(PATH_MAX * sizeof(char));
            strcpy(readblacklist->str, str);
        }
        else if (flag == 3) {
            struct Blacklist *tmp = writeblacklist;
            writeblacklist = (struct Blacklist *)malloc(sizeof(struct Blacklist));
            writeblacklist->next = tmp;
            writeblacklist->str = (char *)malloc(PATH_MAX * sizeof(char));
            strcpy(writeblacklist->str, str);
        }
        else if (flag == 4) {
            struct Blacklist *tmp = connectblacklist;
            connectblacklist = (struct Blacklist *)malloc(sizeof(struct Blacklist));
            connectblacklist->next = tmp;
            connectblacklist->str = (char *)malloc(PATH_MAX * sizeof(char));
            strcpy(connectblacklist->str, str);
        }
        else if (flag == 5) {
            struct Blacklist *tmp = getaddrinfoblacklist;
            getaddrinfoblacklist = (struct Blacklist *)malloc(sizeof(struct Blacklist));
            getaddrinfoblacklist->next = tmp;
            getaddrinfoblacklist->str = (char *)malloc(PATH_MAX * sizeof(char));
            strcpy(getaddrinfoblacklist->str, str);
        }
    }

    free(str);
    fclose(f_conf);
    dlclose(handle);
    
    if (strcmp(function_name, "fopen") == 0) return openblacklist;
    else if (strcmp(function_name, "fread") == 0) return readblacklist;
    else if (strcmp(function_name, "fwrite") == 0) return writeblacklist;
    else if (strcmp(function_name, "connect") == 0) return connectblacklist;
    else if (strcmp(function_name, "getaddrinfo") == 0) return getaddrinfoblacklist;
    else return NULL;
}

char *del_wildcard(char *str) {
    char *ptr = strchr(str, '*');
    char *real_path = (char *)malloc(PATH_MAX * sizeof(char));
    int pos = -1;
    if (ptr != NULL) {
        pos = ptr - str;
        str[pos] = '\0';
        realpath(str, real_path);
        strcat(real_path, "/*");
    }
    else realpath(str, real_path);
    return real_path;
}

char *logfilename(FILE *fp, char *filename) {
    int fno = fileno(fp);
    char proclnk[PATH_MAX];
    ssize_t r;
    sprintf(proclnk, "/proc/self/fd/%d", fno);
    r = readlink(proclnk, filename, 0xFFF);
    if (r < 0)
    {
        printf("failed to readlink\n");
        exit(1);
    }
    filename[r] = '\0';
    // printf("fp -> fno -> filename: %p -> %d -> %s\n", fp, fno, filename);
    return filename;
}

FILE* fopen(const char* pathname, const char* mode) {
    char *output_file = getenv("OUTPUT_FILE");
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    FILE *(*fop)(const char *, const char *) = dlsym(handle, "fopen");

    struct Blacklist *blacklist = getblacklist("fopen");
    realpath(pathname, real_path);
    while (blacklist != NULL) {
        char *real_blacklist = (char *)malloc(PATH_MAX * sizeof(char));
        char path[PATH_MAX];
        strcpy(path, blacklist->str);
        strcpy(real_blacklist, del_wildcard(path));

        if (fnmatch(real_blacklist, real_path, FNM_PATHNAME) == 0) {
            if (output_file == NULL) {
                fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", pathname, mode);
            }
            else {
                FILE *f_out = fop(output_file, "w+");
                fprintf(f_out, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", pathname, mode);
                fclose(f_out);
            }
            errno = EACCES;
            dlclose(handle);
            return NULL;
        }
        blacklist = blacklist->next;
    }

    FILE *rtval = fop(pathname, mode);
    if (output_file == NULL) {
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, rtval);
    }
    else {
        FILE *f_out = fop(output_file, "w+");
        fprintf(f_out, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, rtval);
        fclose(f_out);
    }

    return rtval;
}







// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {

//     // Calculate the total size to be read
//     size_t total_size = size * nmemb;

//     // Allocate a temporary buffer to hold the data read from the stream
//     void* temp_buf = malloc(total_size);
//     if (!temp_buf) {
//         fprintf(stderr, "Error: Memory allocation failed\n");
//         exit(EXIT_FAILURE);
//     }

//     pid_t pid = getpid();
//     //const char* filename_start = strrchr(stream->filename, '/');
//     //const char* filename = (filename_start != NULL) ? filename_start + 1 : stream->filename;
//     char read_filename[256];
//     sprintf(read_filename, "%d--%s--read.log", pid, log_filename);

//     //log_file = fopen(read_filename, "a");
//     log_file = orig_fopen(read_filename, "a");
//     if (!log_file) {
//         fprintf(stderr, "Error opening log file: %s\n", read_filename);
//         exit(EXIT_FAILURE);
//     }

//     // Perform the actual read using the original fread function
//     size_t bytes_read = orig_fread(temp_buf, size, nmemb, stream);

//     // Check if there was any data read
//     if (bytes_read > 0) {
//         // Convert the data buffer to a char pointer for keyword detection
//         char* data = (char*)temp_buf;

//         // Iterate through the data read and check for keywords
//         size_t i;
//         for (i = 0; i < bytes_read; ++i) {
//             size_t j;
//             for (j = 0; j < read_blacklist_size; ++j) {
//                 size_t keyword_len = strlen(read_blacklist[j]);
//                 if (i + keyword_len <= bytes_read && memcmp(data + i, read_blacklist[j], keyword_len) == 0) {
//                     // Keyword found, block access and log
//                     free(temp_buf);  // Free the temporary buffer
//                     errno = EACCES;
//                     fprintf(stderr, "[logger] fread(\"%p\", %zu, %zu, %p) = %zu\n", ptr, size, nmemb, stream, 0);
//                     fprintf(log_file, "[logger] fread(\"%p\", %zu, %zu, %p) = %zu\n", ptr, size, nmemb, stream, 0);
//                     return 0;
//                 }
//             }
//         }

//         // Copy the data back to the original buffer if no keyword was found
//         memcpy(ptr, temp_buf, bytes_read);
//     }

//     free(temp_buf);  // Free the temporary buffer

//     // Log the fread operation
//     fprintf(stderr, "[logger] fread(\"%p\", %zu, %zu, %p) = %zu\n", ptr, size, nmemb, stream, bytes_read);
//     fprintf(log_file, "[logger] fread(\"%p\", %zu, %zu, %p) = %zu\n", ptr, size, nmemb, stream, bytes_read);
//     return bytes_read;

// }



size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char *output_file = getenv("OUTPUT_FILE");
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    FILE *(*fop)(const char *, const char *) = dlsym(handle, "fopen");
    size_t (*fr)(void *ptr, size_t size, size_t nmemb, FILE *stream) = dlsym(handle, "fread");
    size_t total_size = size * nmemb;
    size_t rtval = fr(ptr, size, nmemb, stream);

    struct Blacklist *blacklist = getblacklist("fread");
    while (blacklist != NULL) {
        char *ret = strstr(ptr, blacklist->str);
        if (ret != NULL) {
            if (output_file == NULL) {
                fprintf(stderr, "[logger] fread(%p, %ld, %ld, %p) = 0\n", ptr, size, nmemb, stream);
            }
            else {
                FILE *f_out = fop(output_file, "w+");
                fprintf(f_out, "[logger] fread(%p, %ld, %ld, %p) = 0\n", ptr, size, nmemb, stream);
                fclose(f_out);
            }
            errno = EACCES;
            dlclose(handle);
            return 0;
        }
        blacklist = blacklist->next;
    }

    pid_t pid = getpid();
    char read_filename[PATH_MAX];
    char log_filename[PATH_MAX];
    logfilename(stream, log_filename);
    char *name = strrchr(log_filename, '/');
    char *del = ".";
    char *onlyname = strtok(name+1, del);

    sprintf(read_filename, "%d--%s--read.log", pid, onlyname);

    FILE *log_file = fop(read_filename, "a+");

    if (output_file == NULL) {
        fprintf(stderr, "[logger] fread(%p, %ld, %ld, %p) = %ld\n", ptr, size, nmemb, stream, rtval);
    }
    else {
        FILE *f_out = fop(output_file, "w+");
        fprintf(f_out, "[logger] fread(%p, %ld, %ld, %p) = %ld\n", ptr, size, nmemb, stream, rtval);
        fclose(f_out);
    }

    fprintf(log_file, "%s\n", ptr);
    return rtval;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char *output_file = getenv("OUTPUT_FILE");
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    FILE *(*fop)(const char *, const char *) = dlsym(handle, "fopen");
    size_t (*fwr)(const void *ptr, size_t size, size_t nmemb, FILE *stream) = dlsym(handle, "fwrite");

    char* data = (char*)ptr;
    char write_data[256] = { '\0' };
    int k = 0;
    for(int i = 0; i < strlen(data); i++) {
        if(data[i] == '\n'){
			write_data[k] = '\\';
			write_data[k+1] = 'n';
            k += 1;
		}
		else {
			write_data[k] = data[i];
		}
        k += 1;
	}

    struct Blacklist *blacklist = getblacklist("fwrite");
    while (blacklist != NULL) {
        char *real_blacklist = (char *)malloc(PATH_MAX * sizeof(char));
        char path[PATH_MAX];
        strcpy(path, blacklist->str);
        strcpy(real_blacklist, del_wildcard(path));

        if (fnmatch(real_blacklist, real_path, FNM_PATHNAME) == 0) {
            if (output_file == NULL) {
                fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, %p) = 0\n", write_data, size, nmemb, stream);
            }
            else {
                FILE *f_out = fop(output_file, "w+");
                fprintf(f_out, "[logger] fwrite(\"%s\", %ld, %ld, %p) = 0\n", write_data, size, nmemb, stream);
                fclose(f_out);
            }
            errno = EACCES;
            dlclose(handle);
            return 0;
        }
        blacklist = blacklist->next;
    }

    pid_t pid = getpid();
    char write_filename[PATH_MAX];
    char log_filename[PATH_MAX];
    logfilename(stream, log_filename);
    char *name = strrchr(log_filename, '/');
    char *del = ".";
    char *onlyname = strtok(name+1, del);

    sprintf(write_filename, "%d--%s--write.log", pid, onlyname);

    FILE *log_file = fop(write_filename, "a+");
    size_t rtval = fwr(ptr, size, nmemb, stream);

    if (output_file == NULL) {
        fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, %p) = %ld\n", write_data, size, nmemb, stream, rtval);
    }
    else {
        FILE *f_out = fop(output_file, "w+");
        fprintf(f_out, "[logger] fwrite(\"%s\", %ld, %ld, %p) = %ld\n", write_data, size, nmemb, stream, rtval);
        fclose(f_out);
    }

    fprintf(log_file, "%s\n", write_data);
    return rtval;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char *output_file = getenv("OUTPUT_FILE");
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    FILE *(*fop)(const char *, const char *) = dlsym(handle, "fopen");
    int (*conn)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = dlsym(handle, "connect");
    
    struct Blacklist *blacklist = getblacklist("connect");
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    char *ip = inet_ntoa(addr_in->sin_addr);
    while (blacklist != NULL) {
        if (strcmp(blacklist->str, ip) == 0) {
            if (output_file == NULL) {
                fprintf(stderr, "[logger] connect(%d, \"%s\", %d) = -1\n", sockfd, ip, addrlen);
            }
            else {
                FILE *f_out = fop(output_file, "w+");
                fprintf(f_out, "[logger] connect(%d, \"%s\", %d) = -1\n", sockfd, ip, addrlen);
                fclose(f_out);
            }
            errno = ECONNREFUSED;
            dlclose(handle);
            return -1;
        }
        blacklist = blacklist->next;
    }
    
    int rtval = conn(sockfd, addr, addrlen);

    if (output_file == NULL) {
        fprintf(stderr, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, rtval);
    }
    else {
        // void *handle = dlopen("libc.so.6", RTLD_LAZY);
        FILE *f_out = fop(output_file, "w+");
        fprintf(f_out, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, rtval);
        fclose(f_out);
    }

    dlclose(handle);

    return rtval;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    char *output_file = getenv("OUTPUT_FILE");
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    FILE *(*fop)(const char *, const char *) = dlsym(handle, "fopen");
    int (*getaddr)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = dlsym(handle, "getaddrinfo");
    
    struct Blacklist *blacklist = getblacklist("getaddrinfo");
    while (blacklist != NULL) {
        if (strcmp(blacklist->str, node) == 0) {
            if (output_file == NULL) {
                fprintf(stderr, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", node, service, hints, res, EAI_NONAME);
            }
            else {
                FILE *f_out = fop(output_file, "w+");
                fprintf(f_out, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", node, service, hints, res, EAI_NONAME);
                fclose(f_out);
            }
            dlclose(handle);
            return EAI_NONAME;
        }
        blacklist = blacklist->next;
    }

    int rtval = getaddr(node, service, hints, res);

    if (output_file == NULL) {
        fprintf(stderr, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", node, service, hints, res, rtval);
    }
    else {
        // void *handle = dlopen("libc.so.6", RTLD_LAZY);
        FILE *f_out = fop(output_file, "w+");
        fprintf(f_out, "[logger] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", node, service, hints, res, rtval);
        fclose(f_out);
    }

    dlclose(handle);
    
    return rtval;
}

int system(const char *command) {
    char *output_file = getenv("OUTPUT_FILE");
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    FILE *(*fop)(const char *, const char *) = dlsym(handle, "fopen");
    int (*sys)(const char *) = dlsym(RTLD_NEXT, "system");

    int rtval = sys(command);

    if (output_file == NULL) {
        fprintf(stderr, "[logger] system(\"%s\") = %d\n", command, rtval);
    }
    else {
        FILE *f_out = fop(output_file, "w+");
        fprintf(f_out, "[logger] system(\"%s\") = %d\n", command, rtval);
        fclose(f_out);
    }

    dlclose(handle);

    return rtval;
}