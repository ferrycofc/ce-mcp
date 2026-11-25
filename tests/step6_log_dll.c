#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE self,DWORD reason,LPVOID reserved) {
  if (reason==DLL_PROCESS_ATTACH) {
    HANDLE h=CreateFileA("E:\\workspace\\ce-mcp\\work\\step6-fixture\\dll-loaded.log",
      FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (h!=INVALID_HANDLE_VALUE) {
      const char msg[]="DLL_PROCESS_ATTACH\r\n";
      DWORD written; WriteFile(h,msg,sizeof(msg)-1,&written,NULL); CloseHandle(h);
    }
  }
  return TRUE;
}
