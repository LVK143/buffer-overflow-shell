#include <stdio.h>
#include <string.h>

void vuln() {
      char buffer[64];
      gets (buffer);
}

int main() {
    printf("Welcome to Vulnerabilty  program!\n");
    vuln();
   return 0;
}
