// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define METADATA_SIZE	ALIGN((sizeof(struct block_meta)))
#define MMAP_THRESHOLD (128 * 1024)
#define PAYLOAD(block) ((char *)block + METADATA_SIZE)
#define MIN(a, b) a < b ? a : b

static struct block_meta *memory_block_metas, *last_block;

void set_block_metadata(struct block_meta *meta, size_t payload_size, int status, struct block_meta *prev, struct block_meta *next)
{
  meta->size = payload_size;
  meta->status = status;
  meta->prev = prev;
  meta->next = next;
}

int syscall_fail(void *ptr, char *str)
{
  if (ptr == (void *)-1) {
		DIE(ptr == (void *)-1, str);
		return 1;
	}
  return 0;
}

void preallocate_heap()
{
  void *heap = sbrk(MMAP_THRESHOLD);
  if (syscall_fail(heap, "heap preallocation failed")) return;

  memory_block_metas = (struct block_meta *)heap;
  set_block_metadata(memory_block_metas, MMAP_THRESHOLD - METADATA_SIZE, STATUS_FREE, NULL, NULL);
  last_block = memory_block_metas;
}

void coalesce_current_block(struct block_meta *block, size_t new_payload_size)
{
  while (block && block->next && block->next->status == STATUS_FREE && block->size < new_payload_size) {
    if (block->next == last_block) {
      last_block = block;
    }
    set_block_metadata(block, block->size + METADATA_SIZE + block->next->size, STATUS_FREE, block->prev, block->next->next);
  }
}

void coalesce_all_free_blocks(struct block_meta *block)
{
  while (block && block->next) {
    if (block->status == STATUS_FREE && block->next->status == STATUS_FREE) {
      last_block = (block->next == last_block ? block : last_block);
      set_block_metadata(block, block->size + block->next->size + METADATA_SIZE, STATUS_FREE, block->prev, block->next->next);
    } else {
      block = block->next;
    }
  }
}

void *find_best_available_space(struct block_meta *block, size_t payload_size)
{
  struct block_meta *best_block = NULL;
  coalesce_all_free_blocks(memory_block_metas);
  for (; block != NULL; block = block->next) {
    if ((block->status == STATUS_FREE && block->size >= payload_size) && (best_block == NULL || block->size < best_block->size)) {
      best_block = block;
    }
  }
  return (void *)best_block;
}

void *append_new_block(size_t payload_size)
{
  void *ptr = sbrk(payload_size + METADATA_SIZE);
  if (syscall_fail(ptr, "new block space allocation failed")) return NULL;
  struct block_meta *new_block = (struct block_meta *)ptr;
  set_block_metadata(new_block, payload_size, STATUS_ALLOC, last_block, NULL);
  last_block->next = new_block;
  last_block = new_block;
  return (void *)new_block;
}

void *extend_last_block(size_t payload_size)
{
  void *ptr = sbrk(payload_size - last_block->size);
  if (syscall_fail(ptr, "extend last free block failed")) return NULL;
  set_block_metadata(last_block, payload_size, STATUS_ALLOC, last_block->prev, NULL);
  return (void *)last_block;
}

void check_block_for_splitting(struct block_meta *block, size_t payload_size)
{
  if (block->size - payload_size > METADATA_SIZE) {
    struct block_meta *new_block = (char *)block + METADATA_SIZE + payload_size;
    set_block_metadata(new_block, block->size - (payload_size + METADATA_SIZE), STATUS_FREE, block, block->next);
    set_block_metadata(block, payload_size, STATUS_ALLOC, block->prev, new_block);
    last_block = (block == last_block ? new_block : last_block);
  } else {
    set_block_metadata(block, block->size, STATUS_ALLOC, block->prev, block->next);
  }
}

void *os_malloc(size_t size)
{
  if (size <= 0) {
    return NULL;
  }

  size_t payload_size = ALIGN(size);
  size_t block_size = payload_size + ALIGN(METADATA_SIZE);
  void *new_block;

  if (block_size <= MMAP_THRESHOLD) {
    if (memory_block_metas == NULL) {
      preallocate_heap();
    }

    new_block = find_best_available_space(memory_block_metas, payload_size);

    if (new_block == NULL) {
      new_block = (last_block->status == STATUS_FREE ? extend_last_block(payload_size) : append_new_block(payload_size));
    } else {
      check_block_for_splitting((struct block_meta *)new_block, payload_size);
    }
  } else {
    new_block = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (syscall_fail(new_block, "new block space allocation failed")) return NULL;
    set_block_metadata((struct block_meta*)new_block, payload_size, STATUS_MAPPED, NULL, NULL);
  }
  return PAYLOAD(new_block);
}

void os_free(void *ptr)
{
  if (ptr == NULL) {
    return;
  }
  struct block_meta *block = (struct block_meta *)((char *)ptr - METADATA_SIZE);
  if (block->status == STATUS_ALLOC) {
    block->status = STATUS_FREE;
  }
  if (block->status == STATUS_MAPPED) {
    int call = munmap(block, block->size + METADATA_SIZE);
    if (syscall_fail(call, "free memory block failed")) return NULL;
  }
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0) {
    return NULL;
  }

  size_t payload_size = ALIGN(nmemb * size);
  size_t block_size = payload_size + ALIGN(METADATA_SIZE);
  void *new_block;

  if (block_size <= getpagesize()) {
    if (memory_block_metas == NULL) {
      preallocate_heap();
    }

    new_block = find_best_available_space(memory_block_metas, payload_size);

    if (new_block == NULL) {
      new_block = (last_block->status == STATUS_FREE ? extend_last_block(payload_size) : append_new_block(payload_size));
    } else {
      check_block_for_splitting((struct block_meta *)new_block, payload_size);
    }
  } else {
    new_block = mmap(NULL, block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (syscall_fail(new_block, "new block space allocation failed")) return NULL;
    set_block_metadata((struct block_meta*)new_block, payload_size, STATUS_MAPPED, NULL, NULL);
  }
  memset(PAYLOAD(new_block), 0, payload_size);
  return PAYLOAD(new_block);
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL) {
    return os_malloc(size);
  }
  if (size == 0) {
    os_free(ptr);
    return NULL;
  }

  struct block_meta *block = (struct block_meta *)((char *)ptr - METADATA_SIZE);
  if (block->status == STATUS_FREE) {
    return NULL;
  }

  size_t new_payload_size = ALIGN(size);
  size_t new_block_size = new_payload_size + METADATA_SIZE;

  if (new_payload_size <= MMAP_THRESHOLD && block->status != STATUS_MAPPED) {
    if (block == last_block && block->size < new_payload_size) {
      extend_last_block(new_payload_size);
      return PAYLOAD(block);
    }
    coalesce_current_block(block, new_payload_size);
    if (block->size >= new_payload_size) {
      check_block_for_splitting(block, new_payload_size);
      return PAYLOAD(block);
    }
  }

  void *new_block = os_malloc(new_payload_size);
  memcpy(new_block, PAYLOAD(block), MIN(block->size, new_payload_size));
  os_free(ptr);
  return new_block;
}
