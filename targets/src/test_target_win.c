#include <stdio.h>
#include <string.h>
#include <windows.h>

char *get_secret_key(const char *password) {
    static char key[64];
    snprintf(key, sizeof(key), "KEY::%s::DERIVED", password);
    return key;
}

int check_license(const char *key) {
    if (strncmp(key, "KEY::", 5) == 0) {
        printf("[target] license check: PASS\n");
        return 1;
    }
    printf("[target] license check: FAIL\n");
    return 0;
}

int main(int argc, char **argv) {
    const char *pw = argc > 1 ? argv[1] : "hunter2";
    printf("[target] deriving key from: %s\n", pw);
    char *key = get_secret_key(pw);
    printf("[target] key: %s\n", key);
    int ok = check_license(key);
    printf("[target] result: %s\n", ok ? "licensed" : "unlicensed");
    return ok ? 0 : 1;
}
