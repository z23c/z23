#include <sqlite3.h>
static int mutable_generation = 1;
int bad_service(void) { return sqlite3_open("bad.db", 0) + mutable_generation; }
