#include <stddef.h>
typedef struct { char *original; char *buffer; int length; int size; } datap;
__declspec(dllimport) void BeaconPrintf(int type, const char *fmt, ...);
__declspec(dllimport) void BeaconOutput(int type, const char *data, int len);
__declspec(dllimport) void BeaconDataParse(datap *parser, char *buffer, int size);
void go(char *args, int len) {
    BeaconPrintf(0, "[+] bof says hello\n");
    BeaconOutput(0, args, len);
}
