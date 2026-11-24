/* Independent x86/x64 pointer oracle; no dependency on CE or Python pointer logic. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static struct { uintptr_t pointer; uint32_t poison; } root;
static volatile uint32_t static_value = 0x53799127;
static unsigned char *a, *b, *leaf[2];
static void *reserved, *guarded, *mapped;
static HANDLE mapping;

static void set_pointer(unsigned char *slot, uintptr_t value) {
    const uint32_t poison = 0xf0e1d2c3;
    memcpy(slot, &value, sizeof(value));
    memcpy(slot + sizeof(value), &poison, sizeof(poison));
}

static void select_leaf(int which) { set_pointer(b, (uintptr_t)leaf[which]); }
static int digit(char ch) {
    if (ch >= '0' && ch <= '9') return ch-'0';
    if (ch >= 'a' && ch <= 'f') return ch-'a'+10;
    if (ch >= 'A' && ch <= 'F') return ch-'A'+10;
    return -1;
}

int main(void) {
    char command[300]; DWORD old;
    a = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256);
    b = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256);
    leaf[0] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256);
    leaf[1] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256);
    reserved = VirtualAlloc(NULL, 65536, MEM_RESERVE, PAGE_READWRITE);
    guarded = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    mapped = mapping ? MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 4096) : NULL;
    if (!a || !b || !leaf[0] || !leaf[1] || !reserved || !guarded || !mapped) return 2;
    if (!VirtualProtect(guarded, 4096, PAGE_READWRITE | PAGE_GUARD, &old)) return 3;
    root.pointer = (uintptr_t)a; root.poison = 0xf0e1d2c3;
    set_pointer(a+0x20, (uintptr_t)b+0x10);
    select_leaf(0);
    { uint32_t v=0x12345678; memcpy(leaf[0]+0x38, &v, 4); v=0x23456789; memcpy(leaf[1]+0x38, &v, 4); }
    printf("{\"pid\":%lu,\"pointer_size\":%zu,\"base\":\"%p\",\"root\":\"%p\","
           "\"node_a\":\"%p\",\"node_b\":\"%p\",\"leaf0\":\"%p\",\"leaf1\":\"%p\","
           "\"static_value\":\"%p\",\"code\":\"%p\",\"reserved\":\"%p\",\"guarded\":\"%p\",\"mapped\":\"%p\"}\n",
           GetCurrentProcessId(), sizeof(void*), GetModuleHandleW(NULL), &root.pointer,
           a, b, leaf[0]+0x38, leaf[1]+0x38, &static_value, main, reserved, guarded, mapped);
    fflush(stdout);
    while (fgets(command, sizeof(command), stdin)) {
        int which, length;
        if (sscanf_s(command, "select %d", &which)==1 && which>=0 && which<=1) {
            select_leaf(which); printf("{}\n");
        } else if (strncmp(command, "middle_null", 11)==0) {
            set_pointer(b, 0); printf("{}\n");
        } else if (sscanf_s(command, "null %d", &which)==1 && which>=0 && which<=1) {
            root.pointer = which ? 0 : (uintptr_t)a; printf("{}\n");
        } else if (sscanf_s(command, "bytes %d %d", &which, &length)==2 && which>=0 && which<=1 && length>=1 && length<=128) {
            printf("{\"hex\":\"");
            for (int i=0; i<length; ++i) printf("%02X", leaf[which][0x38+i]);
            printf("\"}\n");
        } else if (strncmp(command, "put ", 4)==0) {
            char hex[257];
            if (sscanf_s(command, "put %d %256s", &which, hex, (unsigned)sizeof(hex))==2 && which>=0 && which<=1) {
                size_t len=strlen(hex); int valid=(len%2==0 && len<=256);
                for (size_t i=0; i<len; ++i) if (digit(hex[i])<0) valid=0;
                if (valid) for (size_t i=0; i<len/2; ++i) leaf[which][0x38+i]=(unsigned char)(digit(hex[i*2])*16+digit(hex[i*2+1]));
                printf(valid ? "{}\n" : "{\"error\":\"invalid hex\"}\n");
            } else printf("{\"error\":\"invalid put\"}\n");
        } else if (strncmp(command, "exit", 4)==0) break;
        else printf("{\"error\":\"unknown command\"}\n");
        fflush(stdout);
    }
    UnmapViewOfFile(mapped); CloseHandle(mapping);
    VirtualFree(reserved, 0, MEM_RELEASE); VirtualFree(guarded, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, a); HeapFree(GetProcessHeap(), 0, b);
    HeapFree(GetProcessHeap(), 0, leaf[0]); HeapFree(GetProcessHeap(), 0, leaf[1]);
    return 0;
}
