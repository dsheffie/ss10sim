/* A freestanding /sbin/init that keeps Linux busy in user space: no libc, raw
 * sparc32 Linux syscalls (ta 0x10, number in %g1, carry set on error).  It runs
 * /bin/w0, /bin/w1, ... in turn (fork, execve, wait4), starting over at w0
 * after the first one that is missing, and never exits -- so a co-sim sample
 * anywhere past boot lands in process creation, exec, page faults, syscalls or
 * the workloads' own code (mkroot.sh installs them). */
static long sys3(long n, long a, long b, long c) {
  register long g1 asm("g1") = n;
  register long o0 asm("o0") = a;
  register long o1 asm("o1") = b;
  register long o2 asm("o2") = c;
  asm volatile("ta 0x10\n\t"
	       "bcs,a 1f\n\t"
	       " sub %%g0, %%o0, %%o0\n"
	       "1:"
	       : "+r"(o0) : "r"(g1), "r"(o1), "r"(o2) : "memory", "cc");
  return o0;
}

static long sys4(long n, long a, long b, long c, long d) {
  register long g1 asm("g1") = n;
  register long o0 asm("o0") = a;
  register long o1 asm("o1") = b;
  register long o2 asm("o2") = c;
  register long o3 asm("o3") = d;
  asm volatile("ta 0x10\n\t"
	       "bcs,a 1f\n\t"
	       " sub %%g0, %%o0, %%o0\n"
	       "1:"
	       : "+r"(o0) : "r"(g1), "r"(o1), "r"(o2), "r"(o3) : "memory", "cc");
  return o0;
}

/* sparc fork: %o0 = the pid, %o1 = 1 in the child, 0 in the parent */
static long sys_fork(long *is_child) {
  register long g1 asm("g1") = 2;
  register long o0 asm("o0");
  register long o1 asm("o1");
  asm volatile("ta 0x10\n\t"
	       "bcs,a 1f\n\t"
	       " sub %%g0, %%o0, %%o0\n"
	       "1:"
	       : "=r"(o0), "=r"(o1) : "r"(g1) : "memory", "cc");
  *is_child = o1;
  return o0;
}

#define SYS_EXIT 1
#define SYS_WRITE 4
#define SYS_WAIT4 7
#define SYS_EXECVE 59

static unsigned slen(const char *s) {
  unsigned n = 0;
  while(s[n]) {
    n++;
  }
  return n;
}

static void say(const char *s) {
  sys3(SYS_WRITE, 1, (long)s, slen(s));
}

static void say_num(long v) {
  char b[24];
  int i = 23;
  int neg = v < 0;
  unsigned long u = neg ? -(unsigned long)v : (unsigned long)v;
  b[i] = 0;
  do {
    b[--i] = '0' + (u % 10);
    u /= 10;
  } while(u != 0);
  if(neg) {
    b[--i] = '-';
  }
  say(&b[i]);
}

void _start(void) {
  char path[] = "/bin/w0000";
  long round = 0;
  say("workinit: running /bin/w*\n");
  for(;;) {
    for(long k = 0; ; k++) {
      path[6] = '0' + (k / 1000) % 10;
      path[7] = '0' + (k / 100) % 10;
      path[8] = '0' + (k / 10) % 10;
      path[9] = '0' + k % 10;
      char *argv[2] = {path, 0};
      char *envp[1] = {0};
      long child = 0;
      long pid = sys_fork(&child);
      if(pid < 0) {
	say("workinit: fork failed\n");
	break;
      }
      if(child) {
	sys3(SYS_EXECVE, (long)path, (long)argv, (long)envp);
	sys3(SYS_EXIT, 127, 0, 0);   /* no such workload: the end of the list */
      }
      int status = 0;
      sys4(SYS_WAIT4, pid, (long)&status, 0, 0);
      if(((status >> 8) & 0xff) == 127) {
	break;
      }
      say("workinit: round ");
      say_num(round);
      say(" ");
      say(path);
      say(" status ");
      say_num(status);
      say("\n");
    }
    round++;
  }
}
