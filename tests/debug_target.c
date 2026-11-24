/* Disposable native fixture. Only these three assembly functions touch watched. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

extern void writer_a(volatile LONG *address, LONG value);
extern void writer_b(volatile LONG *address, LONG value);
extern LONG reader_a(volatile LONG *address);
static volatile LONG watched;
static volatile LONG sink;

int main(void) {
    char command[128];
    printf("{\"pid\":%lu,\"tid\":%lu,\"base\":\"%p\",\"address\":\"%p\","
           "\"writer_a\":\"%p\",\"writer_b\":\"%p\",\"reader_a\":\"%p\"}\n",
           GetCurrentProcessId(), GetCurrentThreadId(), GetModuleHandleW(NULL), &watched, writer_a, writer_b, reader_a);
    fflush(stdout);
    while (fgets(command, sizeof(command), stdin)) {
        int count = 0;
        if (sscanf_s(command, "run %d", &count) == 1 && count >= 0 && count <= 100000) {
            for (int i = 0; i < count; ++i) {
                writer_a(&watched, 0x11223344 + i);
                writer_b(&watched, 0x55667700 + i);
                sink = reader_a(&watched);
            }
            printf("{\"done\":%d}\n", count);
        } else if (strncmp(command, "value", 5) == 0) {
            printf("{\"value\":%ld}\n", watched);
        } else if (strncmp(command, "exit", 4) == 0) {
            break;
        } else {
            printf("{\"error\":\"unknown command\"}\n");
        }
        fflush(stdout);
    }
    return 0;
}
