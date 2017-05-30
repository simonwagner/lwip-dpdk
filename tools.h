#ifndef TOOLS_H
#define TOOLS_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif


static inline uint64_t rdtscp( uint32_t* aux )
{
    uint64_t rax,rdx;
    asm volatile ( "rdtscp\n" : "=a" (rax), "=d" (rdx), "=c" (*aux) : : );
    return (rdx << 32) + rax;
}

void hexdump(void *mem, unsigned int len);

struct duration {
    struct timespec start;
    struct timespec stop;
    struct timespec additional_duration;
};

static inline void duration_start(struct duration* d)
{
    d->stop = (struct timespec){0, 0};
    d->additional_duration = (struct timespec){0, 0};
    clock_gettime(CLOCK_MONOTONIC, &d->start);
}

static inline void duration_stop(struct duration* d)
{
    clock_gettime(CLOCK_MONOTONIC, &d->stop);
}

static inline void duration_continue(struct duration* d)
{
    //add current duration to additional_duration
    struct timespec additional_duration;
    additional_duration.tv_sec = d->stop.tv_sec - d->start.tv_sec;
    if(d->stop.tv_nsec < d->stop.tv_nsec) {
        additional_duration.tv_sec -= 1;
        additional_duration.tv_nsec = d->stop.tv_nsec + 1000000000LL - d->start.tv_nsec;
    }
    else {
        additional_duration.tv_nsec = d->stop.tv_nsec - d->start.tv_nsec;
    }

    d->additional_duration.tv_sec += additional_duration.tv_sec + additional_duration.tv_nsec / 1000000000LL;
    d->additional_duration.tv_nsec += (additional_duration.tv_nsec + additional_duration.tv_nsec) % 1000000000LL;

    duration_start(d);
}

static inline double timespec_as_sec(struct timespec* ts)
{
    return (double)ts->tv_sec + (double)ts->tv_nsec * 1e-9;
}

static inline double duration_as_sec(struct duration* d)
{
    return timespec_as_sec(&d->stop) - timespec_as_sec(&d->start) + timespec_as_sec(&d->additional_duration);
}

#ifdef __cplusplus
}
#endif

#endif // TOOLS_H
