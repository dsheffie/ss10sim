#ifndef __DISPLAY_HH__
#define __DISPLAY_HH__

#include <cstdint>
#include <string>

struct framebuffer_t;
struct state_t;

/* Showing the framebuffer (TCX or CG14): PNG snapshots (--fb-png, deterministic: at exit and
 * every --fb-png-every instructions) and a live SDL2 window (--sdl, refreshed
 * at most every 33 ms of wall clock; closing it stops the run).  SDL types
 * stay out of this header so only display.cc needs SDL; without HAVE_SDL,
 * --sdl reports that and is ignored.  The window also feeds the Sun keyboard
 * and mouse: click it to capture them, Ctrl+Alt+G to release. */
class fb_display {
public:
  fb_display(framebuffer_t *fb, bool sdl, const std::string &png, uint64_t png_every);
  ~fb_display();
  /* call often (cheap): renders on schedule, polls window events */
  void pump(state_t *s);
  bool write_png(const std::string &fn);
private:
  framebuffer_t *fb;
  uint32_t tex_w = 0, tex_h = 0;              /* the SDL texture size */
  std::string png;
  uint64_t png_every, next_png;
  uint32_t *pixels;                            /* MAX_W * MAX_H */
  static const uint32_t MAX_W = 1280, MAX_H = 1024;
  void *win = nullptr, *ren = nullptr, *tex = nullptr;
  uint32_t last_ms = 0;
  uint64_t last_gen = ~0ULL;
  bool grabbed = false;
  void set_grab(bool on);
};

#endif
