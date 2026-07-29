//go:build darwin && cgo

#ifndef MODBIT_FSEVENTS_SHIM_H
#define MODBIT_FSEVENTS_SHIM_H

#include <CoreServices/CoreServices.h>
#include <stdint.h>

// modbit_fsevents_start opens a recursive FSEvents stream over path and delivers every event to
// Go via goFSEventsDeliver, tagged with handle. Returns NULL if the stream could not be started.
FSEventStreamRef modbit_fsevents_start(const char *path, double latency, uintptr_t handle);

// modbit_fsevents_stop stops, invalidates, and releases a stream. Safe with NULL.
void modbit_fsevents_stop(FSEventStreamRef stream);

#endif
