// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"
#include <sys/mman.h>

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT + 1))
#define METADATA_SIZE		(sizeof(struct block_meta))
#define MMAP_THRESHOLD		(128 * 1024)

struct block_meta *memory_bloc_meta;

void set_block_metadata(struct block_meta *meta, int size, int status, struct block_meta *next, struct block_meta *prev) {
  meta->size = size;
  meta->status = status;
  meta->next = next;
  meta->prev = prev;
}

void *os_malloc(size_t size)
{
  if (size <= 0) {
    return NULL;
  }
  void *block = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (block == MAP_FAILED) {
    DIE(block == MAP_FAILED, "malloc mmap allocation failed");
    return NULL;
  }
  set_block_metadata((struct block_meta*)block, size, STATUS_MAPPED, NULL, NULL);
  return block + METADATA_SIZE;
}

void os_free(void *ptr)
{
  if (ptr == NULL) {
    return;
  }
  struct block_meta *meta = (struct block_meta *)((char *)ptr - METADATA_SIZE);
  if (meta->status == STATUS_ALLOC) {
    meta->status == STATUS_FREE;
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
