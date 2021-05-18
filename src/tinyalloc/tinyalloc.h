#pragma once

#include <cstdbool>
#include <cstddef>

namespace tinyalloc
{
    typedef struct Block Block;

    struct Block
    {
        void *addr;
        Block *next;
        size_t size;
    };

    typedef struct
    {
        Block *free;  // first free block
        Block *used;  // first used block
        Block *fresh; // first available blank block
        size_t top;   // top free addr
    } Heap;

    typedef struct
    {
        Heap *heap = NULL;
        const void *heap_limit = NULL;
        size_t heap_split_thresh;
        size_t heap_alignment;
        size_t heap_max_blocks;
    } HeapAllocator;

    bool ta_init(HeapAllocator *a, const void *base, const void *limit, const size_t heap_blocks, const size_t split_thresh, const size_t alignment);
    void *ta_alloc(HeapAllocator *a, size_t num);
    void *ta_calloc(HeapAllocator *a, size_t num, size_t size);
    bool ta_free(HeapAllocator *a, void *ptr);
    size_t ta_blocksize(HeapAllocator *a, void *ptr);

    size_t ta_num_free(HeapAllocator *a);
    size_t ta_num_used(HeapAllocator *a);
    size_t ta_num_fresh(HeapAllocator *a);
    bool ta_check(HeapAllocator *a);

};
