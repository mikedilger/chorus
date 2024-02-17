# Performance

At the time of this writing, I don't know if chorus is fast or not. It has not been
profiled or optimized yet. It has only been designed for performance.

Here are the design choices made in order to help achieve eventual high performance:

- Rust language: low level language runs as fast as your hardware with no runtime and no overhead.
- Asynchronous multithreading: maximizes the utilization of each and every CPU core available.
- Memory mapped storage: Accessing persistent storage is usually just as fast as accessing main
memory (once swapped in). This is achieved via a custom memory map for events and LMDB for indices.
- The event memory map is append-only making it almost lock-free (limited to one writer at a time, but unlimited readers who can read while writes are happening)
- Direct indexing: indices yield the memory offset of the event, not an ID that requires yet another b-tree lookup to fetch the actual event data.
- Events and filters are custom binary structures with in-place zero-copy field access.
- Events and filters have custom JSON parsing that uses very little (usually no) memory allocation.

