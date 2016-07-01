#include "misc.h"

/* returns the time in ms*/
double cputime () {
  struct rusage rus;

  getrusage (RUSAGE_SELF, &rus);
  return ( (double)rus.ru_utime.tv_sec * 1000 + (double)rus.ru_utime.tv_usec / 1000 );
}


int msglevel=1;	/* default debug messages level (higher = more messages...) */

#if defined(NDEBUG) && defined(__GNUC__)
/* Nothing. pmesg has been "defined away" in misc.h already. */
#else
void pmesg(int level, char* format, ...) {
#ifdef NDEBUG
	/* Empty body, so a good compiler will optimise calls
	   to pmesg away */
#else
        va_list args;

        if (level>msglevel)
                return;

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
#endif /* NDEBUG */
}

void gmp_pmesg(int level, char* format, ...) {
#ifdef NDEBUG
	/* Empty body, so a good compiler will optimise calls
	   to pmesg away */
#else
        va_list args;

        if (level>msglevel)
                return;

        va_start(args, format);
        gmp_vfprintf(stderr, format, args);
        va_end(args);
#endif /* NDEBUG */
}

#endif /* NDEBUG && __GNUC__ */
