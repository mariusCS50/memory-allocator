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

void insert_new_block(struct block_meta *meta, size_t size, int status,
                      struct block_meta *prev, struct block_meta *next) {
  set_block_metadata(meta, size, status, prev, next);
  last_block->next = meta;
  last_block = meta;
}

void set_block_metadata(struct block_meta *meta, size_t size, int status,
                        struct block_meta *prev, struct block_meta *next) {
  meta->size = size;
  meta->status = status;
  meta->prev = prev;
  meta->next = next;
}

void preallocate_heap() {
  void *heap = sbrk(MMAP_THRESHOLD);
  if (heap == (void *)-1) {
		DIE(heap == (void *)-1, "heap preallocation failed");
		return NULL;
	}

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
      void *ptr = sbrk(block_size);
      if (ptr == (void *)-1) {
		    DIE(ptr == (void *)-1, "heap preallocation failed");
		    return NULL;
	    }

      new_block = (struct block_meta *)ptr;
      insert_new_block(new_block, payload_size, STATUS_ALLOC, last_block, NULL);
    }
    return (char *)new_block + METADATA_SIZE;
  }

  void *new_block = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

  if (new_block == MAP_FAILED) {
    DIE(new_block == MAP_FAILED, "malloc mmap allocation failed");
    return NULL;
  }

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
