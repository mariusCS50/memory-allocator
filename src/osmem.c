// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include "osmem.h"
#include "block_meta.h"
#include "printf.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define METADATA_SIZE	(sizeof(struct block_meta))
#define MMAP_THRESHOLD (128 * 1024)

static struct block_meta *block_metadata, *last_block;

void set_block_metadata(struct block_meta *meta, size_t size, int status,
                        struct block_meta *prev, struct block_meta *next) {
  meta->size = size;
  meta->status = status;
  meta->prev = prev;
  meta->next = next;
}

int syscall_fail(void *ptr, char *str) {
  if (ptr == (void *)-1) {
		DIE(ptr == (void *)-1, str);
		return 1;
	}
  return 0;
}

void preallocate_heap() {
  void *heap = sbrk(MMAP_THRESHOLD);
  if (syscall_fail(heap, "heap preallocation fail")) return;

  block_metadata = (struct block_meta *)heap;
  set_block_metadata(block_metadata, MMAP_THRESHOLD - METADATA_SIZE, STATUS_FREE, NULL, NULL);
  last_block = block_metadata;
}

struct block_meta *find_best_available_space(struct block_meta *meta, size_t payload_size) {
  struct block_meta *best_block = NULL;
  for (; meta != NULL; meta = meta->next) {
    if (meta->status == STATUS_FREE && meta->size >= payload_size) {
        best_block = meta;
    }
  }
  return best_block;
}

struct block_meta *append_new_block(size_t size, int status) {
  void *ptr = sbrk(size + METADATA_SIZE);
  if (syscall_fail(ptr, "new block space allocation failed")) return NULL;
  struct block_meta *new_block = (struct block_meta *)ptr;
  set_block_metadata(new_block, size, status, last_block, NULL);
  last_block->next = new_block;
  last_block = new_block;
  return new_block;
}

struct block_meta *extend_last_block(size_t payload_size) {
  void *ptr = sbrk(payload_size - last_block->size);
  if (syscall_fail(ptr, "extend last free block fail")) return NULL;
  set_block_metadata(last_block, payload_size, STATUS_ALLOC, last_block->prev, NULL);
  return last_block;
}

void *os_malloc(size_t size)
{
  if (size <= 0) {
    return NULL;
  }

  size_t payload_size = ALIGN(size);
  size_t block_size = ALIGN(size + METADATA_SIZE);

  if (block_size <= MMAP_THRESHOLD) {
    if (block_metadata == NULL) {
      preallocate_heap();
    }

    struct block_meta *new_block = find_best_available_space(block_metadata, payload_size);

    if (new_block) {
      new_block->status = STATUS_ALLOC;
    } else {
      if (last_block->status == STATUS_FREE) {
        new_block = extend_last_block(payload_size);
      } else {
        new_block = append_new_block(payload_size, STATUS_ALLOC);
      }
    }
    return (char *)new_block + METADATA_SIZE;
  }

  void *new_block = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (syscall_fail(new_block, "new block space allocation fail")) return NULL;
  set_block_metadata((struct block_meta*)new_block, payload_size, STATUS_MAPPED, NULL, NULL);
  return (char *)new_block + METADATA_SIZE;
}

void os_free(void *ptr)
{
  if (ptr == NULL) {
    return;
  }
  struct block_meta *meta = (struct block_meta *)((char *)ptr - METADATA_SIZE);
  if (meta->status == STATUS_ALLOC) {
    meta->status = STATUS_FREE;
  }
  if (meta->status == STATUS_MAPPED) {
    munmap(meta, meta->size + METADATA_SIZE);
  }
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
