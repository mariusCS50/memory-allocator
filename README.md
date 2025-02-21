# Memory Allocator

This repository contains a custom dynamic memory allocator written in C as part of a university assignment. The implementation provides custom versions of `os_malloc()`, `os_calloc()`, `os_realloc()`, and `os_free()` by managing memory with low-level system calls such as `sbrk()`, `mmap()`, and `munmap()`. The allocator minimizes syscall overhead by preallocating the heap and reusing freed blocks with block splitting and coalescing.

## Features

- **Custom Memory Allocation Functions**
  - `os_malloc(size_t size)`
  - `os_calloc(size_t nmemb, size_t size)`
  - `os_realloc(void *ptr, size_t size)`
  - `os_free(void *ptr)`
- **Efficient Memory Management**
  - Preallocation of a 128 KB heap using `sbrk()`
  - Block splitting when a free block is larger than needed
  - Coalescing adjacent free blocks to reduce fragmentation
  - Uses `mmap()`/`munmap()` for large allocations
- **Low-Level Error Handling**
  - Every syscall is checked for errors using a dedicated `syscall_fail()` function

## Building the Project

A Makefile is provided for building the memory allocator library. To compile the project:

```bash
make -C src
```

This compiles the source in `src/osmem.c` together with its dependencies.

## Running Tests

Testing is automated using a Python script and a suite of C test cases. Once you've built the library, you can run tests as follows:

```bash
python3 tests/run_tests.py
```

Alternatively, from the `tests/` directory you can run `make check` to compile and execute all test snippets.

## Running the Checker

This assignment uses an automated checker based on Docker to ensure correctness and code style.

**Local Checker:**

1. Make sure Docker is installed.
2. Build the Docker container by running:

```<console
./local.sh docker build
```

3. Execute the checker inside the container with:

```console
./local.sh checker
```

4. Fast Run Automated Tests and Grade (no linter, no prebuilds):
   ```bash
   cd tests
   make check
   ```

**Remote Checker:**

Push your changes to your private fork hosted on GitLab. The GitLab pipeline will automatically build your project, run the tests, and perform style checks.

For detailed instructions, please refer to the [VMChecker Student Handbook](https://github.com/systems-cs-pub-ro/vmchecker-next/wiki/Student-Handbook) and the contents of `README.checker.md`.

## Implementation Details

The core allocator is implemented in [`src/osmem.c`](src/osmem.c):

- **Metadata Management:**
  Functions like `set_block_metadata()` initialize block headers containing size, status, and links to adjacent blocks.
- **Heap Preallocation:**
  On the first small allocation, `preallocate_heap()` reserves 128 KB of memory via `sbrk()` to reduce future syscall overhead.
- **Block Splitting and Coalescing:**
  `check_block_for_splitting()` splits oversized free blocks, while `coalesce_current_block()` and `coalesce_all_free_blocks()` merge adjacent free blocks.
- **Allocation Strategies:**
  Small allocations (below the MMAP threshold) are handled using the preallocated heap; larger requests use `mmap()`.

## Usage Example

After building the project, you can run a simple test as follows:

```bash
make -C src
python3 tests/run_tests.py
```

This sequence compiles the allocator and runs tests that verify allocations, deallocations, reallocations, block splitting, and coalescing.