#include <windows.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  char line[64];
  printf("%lu\n", GetCurrentProcessId()); fflush(stdout);
  while (fgets(line,sizeof(line),stdin)) {
    if (!strncmp(line,"tick",4)) {
      ULONGLONG start=GetTickCount64();
      Sleep(1000);
      printf("%llu\n",(unsigned long long)(GetTickCount64()-start)); fflush(stdout);
    } else if (!strncmp(line,"exit",4)) break;
  }
  return 0;
}
