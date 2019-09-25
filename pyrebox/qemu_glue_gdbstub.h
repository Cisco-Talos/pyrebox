#ifndef QEMU_GLUE_GDBSTUB
#define QEMU_GLUE_GDBSTUB

/* GDB breakpoint/watchpoint types */
#define GDB_BREAKPOINT_SW        0
#define GDB_BREAKPOINT_HW        1
#define GDB_WATCHPOINT_WRITE     2
#define GDB_WATCHPOINT_READ      3
#define GDB_WATCHPOINT_ACCESS    4

// Initialize a gdb session on a given port.
int pyrebox_gdbserver_start(unsigned int port);

// Function that must be called when a debugged process
// exits. It signals the attached GDB (if any), closing
// the session.
void pyrebox_gdb_exit(int code);

// Send attached GDB a packet to close the debugging
// session.
void pyrebox_gdbserver_cleanup(void);

void gdb_signal_breakpoint(unsigned long long thread);


#endif
