#include <windows.h>
#include <string.h>
BOOL WINAPI DllMain(HINSTANCE self,DWORD reason,LPVOID reserved) {
  if (reason==DLL_PROCESS_ATTACH) {
    char path[MAX_PATH];
    DWORD length=GetModuleFileNameA(self,path,MAX_PATH);
    if (length==0 || length>=MAX_PATH) return TRUE;
    while (length>0 && path[length-1]!='\\' && path[length-1]!='/') --length;
    if (length==0) return TRUE;
    if (strcpy_s(path+length,MAX_PATH-length,"dll-loaded.log")!=0) return TRUE;
    HANDLE h=CreateFileA(path,
      FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (h!=INVALID_HANDLE_VALUE) {
      const char msg[]="DLL_PROCESS_ATTACH\r\n";
      DWORD written; WriteFile(h,msg,sizeof(msg)-1,&written,NULL); CloseHandle(h);
    }
  }
  return TRUE;
}
