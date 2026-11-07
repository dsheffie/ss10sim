#include <cstdio>
#include <png.h>

#include "display.hh"
#include "interpret.hh"
#include "sun4m.hh"
#include "fb.hh"
#include "keymap.hh"

#ifdef HAVE_SDL
#include <SDL.h>


/* SDL mouse buttons -> Sun mouse (bit 2 left, 1 middle, 0 right) */
static uint8_t sun_buttons(uint32_t m) {
  uint8_t b = 0;
  if(m & SDL_BUTTON_LMASK) {
    b |= 0x4;
  }
  if(m & SDL_BUTTON_MMASK) {
    b |= 0x2;
  }
  if(m & SDL_BUTTON_RMASK) {
    b |= 0x1;
  }
  return b;
}
#endif

fb_display::fb_display(framebuffer_t *fb, bool sdl, const std::string &png, uint64_t png_every) :
  fb(fb), png(png), png_every(png_every), next_png(png_every) {
  pixels = new uint32_t[MAX_W * MAX_H];
  if(not sdl) {
    return;
  }
#ifdef HAVE_SDL
  if(SDL_Init(SDL_INIT_VIDEO) != 0) {
    fprintf(stderr, "ss10sim: sdl: SDL_Init failed: %s\n", SDL_GetError());
    return;
  }
  SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, "1");
  SDL_Window *w = SDL_CreateWindow("ss10sim", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
				   fb->width(), fb->height(), SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
  if(w == nullptr) {
    fprintf(stderr, "ss10sim: sdl: CreateWindow failed: %s\n", SDL_GetError());
    SDL_Quit();
    return;
  }
  SDL_Renderer *r = SDL_CreateRenderer(w, -1, SDL_RENDERER_ACCELERATED);   /* no vsync: never block the sim */
  if(r == nullptr) {
    r = SDL_CreateRenderer(w, -1, 0);
  }
  win = w;
  ren = r;
  set_grab(false);
#else
  fprintf(stderr, "ss10sim: --sdl: built without SDL2 (no sdl2-config); use --fb-png\n");
#endif
}

fb_display::~fb_display() {
  if(not png.empty()) {
    write_png(png);
  }
#ifdef HAVE_SDL
  if(tex) {
    SDL_DestroyTexture(static_cast<SDL_Texture *>(tex));
  }
  if(ren) {
    SDL_DestroyRenderer(static_cast<SDL_Renderer *>(ren));
  }
  if(win) {
    SDL_DestroyWindow(static_cast<SDL_Window *>(win));
    SDL_Quit();
  }
#endif
  delete [] pixels;
}

void fb_display::set_grab(bool on) {
#ifdef HAVE_SDL
  grabbed = on;
  SDL_SetRelativeMouseMode(on ? SDL_TRUE : SDL_FALSE);
  SDL_SetWindowTitle(static_cast<SDL_Window *>(win), on ? "ss10sim TCX -- captured; Ctrl+Alt+G to release"
						     : "ss10sim TCX -- click to capture keyboard+mouse");
#else
  (void)on;
#endif
}

bool fb_display::write_png(const std::string &fn) {
  FILE *fp = fopen(fn.c_str(), "wb");
  if(fp == nullptr) {
    fprintf(stderr, "ss10sim: cannot write %s\n", fn.c_str());
    return false;
  }
  png_structp p = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  png_infop info = png_create_info_struct(p);
  if(setjmp(png_jmpbuf(p))) {
    png_destroy_write_struct(&p, &info);
    fclose(fp);
    return false;
  }
  png_init_io(p, fp);
  const uint32_t w = fb->width(), h = fb->height();
  png_set_IHDR(p, info, w, h, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
	       PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
  png_write_info(p, info);
  fb->render(pixels);
  uint8_t row[MAX_W * 3];
  for(uint32_t y = 0; y < h; y++) {
    for(uint32_t x = 0; x < w; x++) {
      const uint32_t c = pixels[y * w + x];
      row[3 * x] = c >> 16;
      row[3 * x + 1] = c >> 8;
      row[3 * x + 2] = c;
    }
    png_write_row(p, row);
  }
  png_write_end(p, nullptr);
  png_destroy_write_struct(&p, &info);
  fclose(fp);
  return true;
}

void fb_display::pump(state_t *s) {
  if(png_every != 0 and s->icnt >= next_png) {
    /* a %llu in the name numbers the snapshots by icount (else each one
     * replaces the last) */
    char name[512];
    snprintf(name, sizeof(name), png.c_str(), static_cast<unsigned long long>(s->icnt));
    write_png(png.find('%') != std::string::npos ? std::string(name) : png);
    next_png = s->icnt + png_every;
  }
#ifdef HAVE_SDL
  if(win == nullptr) {
    return;
  }
  /* input: clicking the window captures keyboard and mouse, Ctrl+Alt+G
   * releases them */
  SDL_Event e;
  bool input = false;
  while(SDL_PollEvent(&e)) {
    switch(e.type)
      {
      case SDL_QUIT:
	s->brk = true;
	break;
      case SDL_MOUSEBUTTONDOWN:
      case SDL_MOUSEBUTTONUP:
	if(not grabbed) {
	  if(e.type == SDL_MOUSEBUTTONDOWN) {
	    set_grab(true);
	  }
	  break;
	}
	s->sun4m->kbd_ms.mouse_event(0, 0, sun_buttons(SDL_GetMouseState(nullptr, nullptr)));
	input = true;
	break;
      case SDL_MOUSEMOTION:
	if(grabbed) {
	  s->sun4m->kbd_ms.mouse_event(e.motion.xrel, e.motion.yrel, sun_buttons(e.motion.state));
	  input = true;
	}
	break;
      case SDL_KEYDOWN:
      case SDL_KEYUP: {
	if(not grabbed or e.key.repeat) {
	  break;
	}
	const SDL_Keymod mod = SDL_GetModState();
	if(e.key.keysym.scancode == SDL_SCANCODE_G and (mod & KMOD_CTRL) and (mod & KMOD_ALT)) {
	  set_grab(false);
	  break;
	}
	const uint32_t sc = e.key.keysym.scancode;
	const uint8_t k = usb_to_sun(sc);
	if(k != 0) {
	  s->sun4m->kbd_ms.kbd_event(k, e.type == SDL_KEYDOWN);
	  input = true;
	}
	break;
      }
      default:
	break;
      }
  }
  if(input) {
    s->sun4m->update_irqs(s);
  }
  const uint32_t now = SDL_GetTicks();
  if(now - last_ms < 33) {
    return;
  }
  last_ms = now;
  if(fb->gen == last_gen) {
    return;
  }
  last_gen = fb->gen;
  fb->render(pixels);
  const uint32_t w = fb->width(), h = fb->height();
  if(w != tex_w or h != tex_h) {             /* first frame, or the mode changed */
    if(tex) {
      SDL_DestroyTexture(static_cast<SDL_Texture *>(tex));
    }
    tex = SDL_CreateTexture(static_cast<SDL_Renderer *>(ren), SDL_PIXELFORMAT_ARGB8888,
			    SDL_TEXTUREACCESS_STREAMING, w, h);
    SDL_RenderSetLogicalSize(static_cast<SDL_Renderer *>(ren), w, h);
    SDL_SetWindowSize(static_cast<SDL_Window *>(win), w, h);
    tex_w = w;
    tex_h = h;
  }
  SDL_UpdateTexture(static_cast<SDL_Texture *>(tex), nullptr, pixels, w * 4);
  SDL_RenderClear(static_cast<SDL_Renderer *>(ren));
  SDL_RenderCopy(static_cast<SDL_Renderer *>(ren), static_cast<SDL_Texture *>(tex), nullptr, nullptr);
  SDL_RenderPresent(static_cast<SDL_Renderer *>(ren));
#endif
}
