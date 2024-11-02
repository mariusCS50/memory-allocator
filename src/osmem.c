// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define METADATA_SIZE	(sizeof(struct block_meta))
#define MMAP_THRESHOLD (128 * 1024)

static struct block_meta *block_metadata;

void set_block_metadata(struct block_meta *meta, size_t size, int status,
                        struct block_meta *prev, struct block_meta *next) {
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

  size_t meta_size = ALIGN(size);
  size_t block_size = meta_size + METADATA_SIZE;

  if (block_size <= MMAP_THRESHOLD) {
    void *new_block = (block_metadata == NULL ? sbrk(MMAP_THRESHOLD) : sbrk(block_size));

    if (new_block == (void *)-1) {
		  DIE(new_block == (void *)-1, "heap preallocation failed");
		  return NULL;
	  }

    if (block_metadata == NULL) {
      block_metadata = (struct block_meta *)new_block;
      set_block_metadata(block_metadata, MMAP_THRESHOLD - METADATA_SIZE, STATUS_ALLOC, NULL, NULL);
    } else {
      struct block_meta *tail = block_metadata;
      while (tail->next) tail = tail->next;
      set_block_metadata(new_block, meta_size, STATUS_ALLOC, tail, NULL);
    }

    return (char *)new_block + METADATA_SIZE;
  }

  void *new_block = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (new_block == MAP_FAILED) {
    DIE(new_block == MAP_FAILED, "malloc mmap allocation failed");
    return NULL;
  }
  set_block_metadata((struct block_meta*)new_block, meta_size, STATUS_MAPPED, NULL, NULL);
  return (char *)new_block + METADATA_SIZE;
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
