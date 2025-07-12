#include <stdio.h>
#include <string.h>

void vuln() {
    char buffer[64];
    gets(buffer); // 💀 Vulnerable: no bounds check
}

int main() {
    printf("Welcome to vulnerable program!\n");
    vuln();
    return 0;
}
