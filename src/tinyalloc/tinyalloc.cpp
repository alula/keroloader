#include "tinyalloc.h"
#include <stdint.h>

#ifdef TA_DEBUG
extern void print_s(char *);
extern void print_i(size_t);
#else
#define print_s(X)
#define print_i(X)
#endif

typedef struct Block Block;

struct Block {
    void *addr;
    Block *next;
    size_t size;
};

typedef struct {
    Block *free;   // first free block
    Block *used;   // first used block
    Block *fresh;  // first available blank block
    size_t top;    // top free addr
} Heap;

typedef struct {
    Heap *heap = NULL;
    const void *heap_limit = NULL;
    size_t heap_split_thresh;
    size_t heap_alignment;
    size_t heap_max_blocks;
} HeapAllocator;

/**
 * If compaction is enabled, inserts block
 * into free list, sorted by addr.
 * If disabled, add block has new head of
 * the free list.
 */
static void insert_block(HeapAllocator* a, Block *block) {
#ifndef TA_DISABLE_COMPACT
    Block *ptr  = a->heap->free;
    Block *prev = NULL;
    while (ptr != NULL) {
        if ((size_t)block->addr <= (size_t)ptr->addr) {
            print_s("insert");
            print_i((size_t)ptr);
            break;
        }
        prev = ptr;
        ptr  = ptr->next;
    }
    if (prev != NULL) {
        if (ptr == NULL) {
            print_s("new tail");
        }
        prev->next = block;
    } else {
        print_s("new head");
        a->heap->free = block;
    }
    block->next = ptr;
#else
    block->next = a->heap->free;
    a->heap->free  = block;
#endif
}

#ifndef TA_DISABLE_COMPACT
static void release_blocks(HeapAllocator* a, Block *scan, Block *to) {
    Block *scan_next;
    while (scan != to) {
        print_s("release");
        print_i((size_t)scan);
        scan_next   = scan->next;
        scan->next  = a->heap->fresh;
        a->heap->fresh = scan;
        scan->addr  = 0;
        scan->size  = 0;
        scan        = scan_next;
    }
}

static void compact(HeapAllocator* a) {
    Block *ptr = a->heap->free;
    Block *prev;
    Block *scan;
    while (ptr != NULL) {
        prev = ptr;
        scan = ptr->next;
        while (scan != NULL &&
               (size_t)prev->addr + prev->size == (size_t)scan->addr) {
            print_s("merge");
            print_i((size_t)scan);
            prev = scan;
            scan = scan->next;
        }
        if (prev != ptr) {
            size_t new_size =
                (size_t)prev->addr - (size_t)ptr->addr + prev->size;
            print_s("new size");
            print_i(new_size);
            ptr->size   = new_size;
            Block *next = prev->next;
            // make merged blocks available
            release_blocks(a, ptr->next, prev->next);
            // relink
            ptr->next = next;
        }
        ptr = ptr->next;
    }
}
#endif

bool ta_init(HeapAllocator* a, const void *base, const void *limit, const size_t heap_blocks, const size_t split_thresh, const size_t alignment) {
    a->heap = (Heap *)base;
    a->heap_limit = limit;
    a->heap_split_thresh = split_thresh;
    a->heap_alignment = alignment;
    a->heap_max_blocks = heap_blocks;

    a->heap->free   = NULL;
    a->heap->used   = NULL;
    a->heap->fresh  = (Block *)(a->heap + 1);
    a->heap->top    = (size_t)(a->heap->fresh + heap_blocks);

    Block *block = a->heap->fresh;
    size_t i     = a->heap_max_blocks - 1;
    while (i--) {
        block->next = block + 1;
        block++;
    }
    block->next = NULL;
    return true;
}

bool ta_free(HeapAllocator* a, void *free) {
    Block *block = a->heap->used;
    Block *prev  = NULL;
    while (block != NULL) {
        if (free == block->addr) {
            if (prev) {
                prev->next = block->next;
            } else {
                a->heap->used = block->next;
            }
            insert_block(a, block);
#ifndef TA_DISABLE_COMPACT
            compact(a);
#endif
            return true;
        }
        prev  = block;
        block = block->next;
    }
    return false;
}

static Block *alloc_block(HeapAllocator* a, size_t num) {
    Block *ptr  = a->heap->free;
    Block *prev = NULL;
    size_t top  = a->heap->top;
    num         = (num + a->heap_alignment - 1) & -a->heap_alignment;
    while (ptr != NULL) {
        const int is_top = ((size_t)ptr->addr + ptr->size >= top) && ((size_t)ptr->addr + num <= (size_t)a->heap_limit);
        if (is_top || ptr->size >= num) {
            if (prev != NULL) {
                prev->next = ptr->next;
            } else {
                a->heap->free = ptr->next;
            }
            ptr->next  = a->heap->used;
            a->heap->used = ptr;
            if (is_top) {
                print_s("resize top block");
                ptr->size = num;
                a->heap->top = (size_t)ptr->addr + num;
#ifndef TA_DISABLE_SPLIT
            } else if (a->heap->fresh != NULL) {
                size_t excess = ptr->size - num;
                if (excess >= a->heap_split_thresh) {
                    ptr->size    = num;
                    Block *split = a->heap->fresh;
                    a->heap->fresh  = split->next;
                    split->addr  = (void *)((size_t)ptr->addr + num);
                    print_s("split");
                    print_i((size_t)split->addr);
                    split->size = excess;
                    insert_block(a, split);
#ifndef TA_DISABLE_COMPACT
                    compact(a);
#endif
                }
#endif
            }
            return ptr;
        }
        prev = ptr;
        ptr  = ptr->next;
    }
    // no matching free blocks
    // see if any other blocks available
    size_t new_top = top + num;
    if (a->heap->fresh != NULL && new_top <= (size_t)a->heap_limit) {
        ptr         = a->heap->fresh;
        a->heap->fresh = ptr->next;
        ptr->addr   = (void *)top;
        ptr->next   = a->heap->used;
        ptr->size   = num;
        a->heap->used  = ptr;
        a->heap->top   = new_top;
        return ptr;
    }
    return NULL;
}

void *ta_alloc(HeapAllocator* a, size_t num) {
    Block *block = alloc_block(a, num);
    if (block != NULL) {
        return block->addr;
    }
    return NULL;
}

static void memclear(void *ptr, size_t num) {
    size_t *ptrw = (size_t *)ptr;
    size_t numw  = (num & -sizeof(size_t)) / sizeof(size_t);
    while (numw--) {
        *ptrw++ = 0;
    }
    num &= (sizeof(size_t) - 1);
    uint8_t *ptrb = (uint8_t *)ptrw;
    while (num--) {
        *ptrb++ = 0;
    }
}

void *ta_calloc(HeapAllocator* a, size_t num, size_t size) {
    num *= size;
    Block *block = alloc_block(a, num);
    if (block != NULL) {
        memclear(block->addr, num);
        return block->addr;
    }
    return NULL;
}

static size_t count_blocks(Block *ptr) {
    size_t num = 0;
    while (ptr != NULL) {
        num++;
        ptr = ptr->next;
    }
    return num;
}

size_t ta_num_free(HeapAllocator* a) {
    return count_blocks(a->heap->free);
}

size_t ta_num_used(HeapAllocator* a) {
    return count_blocks(a->heap->used);
}

size_t ta_num_fresh(HeapAllocator* a) {
    return count_blocks(a->heap->fresh);
}

bool ta_check(HeapAllocator* a) {
    return a->heap_max_blocks == ta_num_free(a) + ta_num_used(a) + ta_num_fresh(a);
}
