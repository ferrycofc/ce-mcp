#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
extern void inject_wide(volatile int *address, int value);
struct Record { int id; float speed; uintptr_t pointer; int common; };
static struct Record first = {11, 1.5f, 0x1234, 77};
static struct Record second = {22, 2.5f, 0x5678, 77};
static volatile int watched;
int main(void) {
  char cmd[128];
  printf("{\"pid\":%lu,\"module\":\"ce_mcp_injection_target.exe\",\"site\":\"%p\",\"watched\":\"%p\",\"first\":\"%p\",\"second\":\"%p\"}\n",
    GetCurrentProcessId(), inject_wide, &watched, &first, &second);
  fflush(stdout);
  while (fgets(cmd,sizeof(cmd),stdin)) {
    int value;
    if (sscanf_s(cmd,"run %d",&value)==1) {
      inject_wide(&watched,value);
      printf("{\"value\":%d}\n",watched);
    } else if (strncmp(cmd,"exit",4)==0) break;
    else printf("{\"error\":\"unknown\"}\n");
    fflush(stdout);
  }
  return 0;
}
