#include "shim.h"
#include <dispatch/dispatch.h>
#include "_cgo_export.h"

// modbit_fsevents_cb runs on the stream's dispatch queue. It does no work beyond handing each
// (path, flags) pair to Go: FSEvents delivers on a serial queue, so anything slow here delays every
// later notification and eats into the freshness budget the watcher is measured against.
static void modbit_fsevents_cb(ConstFSEventStreamRef stream, void *info, size_t count,
                               void *paths, const FSEventStreamEventFlags flags[],
                               const FSEventStreamEventId ids[]) {
    char **entries = (char **)paths;
    uintptr_t handle = (uintptr_t)info;
    for (size_t i = 0; i < count; i++) {
        goFSEventsDeliver(handle, entries[i], (int)flags[i]);
    }
}

FSEventStreamRef modbit_fsevents_start(const char *path, double latency, uintptr_t handle) {
    CFStringRef cfPath = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    if (cfPath == NULL) return NULL;
    CFArrayRef watched = CFArrayCreate(NULL, (const void **)&cfPath, 1, &kCFTypeArrayCallBacks);
    if (watched == NULL) { CFRelease(cfPath); return NULL; }

    // The handle travels as the context's info pointer, which is how the callback finds its source
    // without a Go pointer ever being held by C.
    FSEventStreamContext ctx = {0, (void *)handle, NULL, NULL, NULL};

    // FileEvents gives per-file paths rather than per-directory ones, which is what makes a delta
    // possible at all. NoDefer delivers the first event of a burst immediately and then throttles,
    // so a single edit is fast and a bulk change is still coalesced.
    FSEventStreamRef stream = FSEventStreamCreate(
        NULL, &modbit_fsevents_cb, &ctx, watched,
        kFSEventStreamEventIdSinceNow, latency,
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer);

    CFRelease(watched);
    CFRelease(cfPath);
    if (stream == NULL) return NULL;

    dispatch_queue_t queue = dispatch_queue_create("com.modbit.fsevents", DISPATCH_QUEUE_SERIAL);
    FSEventStreamSetDispatchQueue(stream, queue);
    dispatch_release(queue); // the stream retains it
    if (!FSEventStreamStart(stream)) {
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        return NULL;
    }
    return stream;
}

void modbit_fsevents_stop(FSEventStreamRef stream) {
    if (stream == NULL) return;
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
}
