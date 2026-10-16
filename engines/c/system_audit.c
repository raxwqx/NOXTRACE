/* NOXTRACE C engine: small local-only system snapshot; no network activity. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/types.h>

static void json_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 0x20) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
int main(void) {
    struct utsname info;
    char hostname[256] = {0};
    if (uname(&info) != 0) { perror("uname"); return 1; }
    if (gethostname(hostname, sizeof(hostname) - 1) != 0) { strcpy(hostname, "unknown"); }
    printf("{\n  \"engine\": \"C/local-system\",\n  \"hostname\": "); json_string(hostname);
    printf(",\n  \"system\": "); json_string(info.sysname);
    printf(",\n  \"release\": "); json_string(info.release);
    printf(",\n  \"architecture\": "); json_string(info.machine);
    printf(",\n  \"effective_uid\": %ld,\n  \"network_activity\": false\n}\n", (long)geteuid());
    return 0;
}
