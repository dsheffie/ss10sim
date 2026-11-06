/* A freestanding /sbin/init for the SCSI-disk smoke test: no libc, raw sparc32
 * Linux syscalls (ta 0x10, number in %g1, carry set on error).  It reports that
 * the root on the SCSI disk mounted, writes a file and reads it back (the
 * disk's WRITE path), syncs, and then idles in pause() so the kernel never
 * panics with "Attempted to kill init". */
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

#define SYS_READ 3
#define SYS_WRITE 4
#define SYS_OPEN 5
#define SYS_CLOSE 6
#define SYS_PAUSE 29
#define SYS_SYNC 36
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0x200
#define O_TRUNC 0x400

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
  } while(u);
  if(neg) {
    b[--i] = '-';
  }
  say(b + i);
}

static const char msg[] = "the quick brown fox jumps over the lazy SCSI disk\n";

int main(void) {
  char buf[128];
  say("init: root filesystem on the SCSI disk is mounted\n");
  long fd = sys3(SYS_OPEN, (long)"/scratch", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0) {
    say("init: open for write failed: ");
    say_num(fd);
    say("\n");
  }
  else {
    sys3(SYS_WRITE, fd, (long)msg, sizeof(msg) - 1);
    sys3(SYS_CLOSE, fd, 0, 0);
    sys3(SYS_SYNC, 0, 0, 0);
    fd = sys3(SYS_OPEN, (long)"/scratch", O_RDONLY, 0);
    long n = (fd < 0) ? fd : sys3(SYS_READ, fd, (long)buf, sizeof(buf) - 1);
    if(n == (long)(sizeof(msg) - 1)) {
      buf[n] = 0;
      say("init: read back: ");
      say(buf);
    }
    else {
      say("init: read back failed: ");
      say_num(n);
      say("\n");
    }
  }
  say("init: done, idling\n");
  for(;;) {
    sys3(SYS_PAUSE, 0, 0, 0);
  }
  return 0;
}

static char stack[16384] __attribute__((aligned(16)));
__attribute__((naked)) void _start(void) {
  asm volatile("sethi %%hi(%0+16384-96), %%sp\n\t"
	       "or %%sp, %%lo(%0+16384-96), %%sp\n\t"
	       "call main\n\t nop\n\t"
	       "mov 1, %%g1\n\t ta 0x10\n\t" :: "i"(stack));
}
