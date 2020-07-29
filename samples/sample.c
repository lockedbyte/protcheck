#include <stdio.h>

void dangerous_import(void) {
    system("/bin/id");
    dup2(0, 1);
}

void vuln(void) {
    char buf[500];
    printf("Enter your name: ");
    gets(buf);
    printf("Nice to meet you, %s\n", buf);
}

int main(int argc, char *argv[]) {
    vuln();
    return 0;
}
