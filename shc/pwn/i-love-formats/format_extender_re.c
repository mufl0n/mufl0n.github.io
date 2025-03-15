#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

// Called by `%Debug` fmtstring
int (*debug_func)(const char *s) = puts;   // 0x555555558010

// String to be formatted
char user_input[104];                      // 0x555555558060

// Reads up to `len` characters.
// Trims at first EOL, but otherwise allows zeros!
void *read_input(char *buf, int len) {
    if ( !fgets(buf, len, stdin) ) {
        puts("Fail to read input"); exit(-1);
    }
    char *res = strchr(buf, '\n');
    if (res) *res = 0;
}

// Clean string reversal
// (unless the string itself is already overflowing)
void reverse_str(char *str) {
    int q = strlen(str)-1;
    for (int p=0; p<i; p++, q--) {}
        char c = str[p];
        str[p] = str[q];
        str[q] = c;
    }
}

// Clean string uppercase
// (unless the string itself is already overflowing)
void uppercase_str(char *str) {
    int len = strlen(str);
    for (int i=0; i<len; i++)
        str[i] = toupper(str[i]);
}

// Clean string lowercase
// (unless the string itself is already overflowing)
void lowercase_str(char *str) {
    int len = strlen(str);
    for (int i=0; i<len; i++)
        str[i] = tolower(str[i]);
}

// Runs the command, or `man printf` if NULL
// (`man` should fail, it is being removed in the Dockerfile)
int help(char *arg) {
    if (arg)
        return system(arg);
    else
        return system("man printf | head -n 8");
}

// Checks if `fmtstring` contains one of the format specifiers
// This does not prevent %10d or %10$p though and %n is allowed too
int safer_printf(char *fmtstring) {
    char *patterns[15] = {
        "%p", "%x", "%X", "%d", "%i", "%u", "%o", "%f",
        "%F", "%e", "%E", "%g", "%G", "%a", "%l"
    };
    for (int i=0; i<15; i++)
        if (strstr(fmtstring, patterns[i]))
            return 1;
    return 0;
}

void better_printf(char *fmt) {
    char buf[128];

    memset(buf, 0, sizeof(buf));
    if (!strncmp(fmt, "%Rev", 4)) {
        reverse_str(user_input);
        snprintf(buf, 100, "%s", user_input);
    } else if (!strncmp(fmt, "%Upper", 6)) {
        uppercase_str(user_input);
        snprintf(buf, 100, "%s", user_input);
    } else if (!strncmp(fmt, "%Lower", 6)) {
        lowercase_str(user_input);
        snprintf(buf, 100, "%s", user_input);
    } else if (!strncmp(fmt, "%Debug", 6)) {
        debug_func(user_input);
    } else if (!strncmp(fmt, "%Help", 5)) {
        help(NULL);
    } else if (!strncmp(fmt, "%Exit", 5)) {
        exit(0);
    } else if (safer_printf(fmt)) {
        puts("I like string formats, but not number formats!! >:((");
        return;
    } else {
        // *(better_printf+682)
        snprintf(buf, 100, fmt, user_input);
    }
    printf("Result: %s\n\n", buf);
}


int main(int argc, char **argv, char **envp) {
    char fmt[136];

    memset(fmt, 0, 128);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    // *(main+184)
    puts("Welcome to my new and improved formatter. Just like printf - just better!\n");
    puts("[DISCLAIMER] This is a DEMO version. You get 3 free tries.");
    for (int i=0; i<=2; i++) {
        memset(fmt, 0, 128);
        printf("Enter format specifier > ");
        read_input(fmt, 128);
        printf("Enter your input > ");
        read_input(user_input, 100);
        better_printf(fmt);
    }
    puts("Thank you for trying my custom formatter  ( ^_^) /");
    return 0;
}
