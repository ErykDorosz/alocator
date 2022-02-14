#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "heap.h"
#include "custom_unistd.h"
#include <stdint.h>
#include <assert.h>
#include "tested_declarations.h"
#include "rdebug.h"
#include "tested_declarations.h"
#include "rdebug.h"



struct memory_manager_t manager;



/****/ /****/ /****/
int heap_setup(void)
{
    if( heap_validate()!=2 ) return -1;

    void *start = custom_sbrk(0);
    if( start == (void*)-1 )
        return -1;

    manager.memory_start = start;
    manager.first_memory_chunk = NULL;

    return 0;
}



/****/ /****/ /****/
void heap_clean(void)
{
    if( heap_validate()==2 ) return;

    void *end = custom_sbrk(0);
    if( end == (void*)-1 )
        return;

    void *ptr = custom_sbrk( (uint8_t *)manager.memory_start - (uint8_t *)end );
    if( ptr == (void*)-1 )
        return;

    manager.memory_start = NULL;
    manager.first_memory_chunk = NULL;
}



/****/ /****/ /****/
size_t   heap_get_largest_used_block_size(void)
{
    if( heap_validate() ) return 0;

    struct memory_chunk_t *pcurrent;
    size_t maks=0;

    for (pcurrent = manager.first_memory_chunk; pcurrent != NULL; pcurrent = pcurrent->next)
        if(maks < pcurrent->size && pcurrent->free==0) maks=pcurrent->size;

    return maks;
}



/****/ /****/ /****/
void plotki(void *adres,size_t size)
{
    unsigned char *pom=( unsigned char *)adres;

    memcpy(pom,"###",plot);
    pom+=3;
    pom+=size;
    memcpy(pom,"###",plot);
}



/****/ /****/ /****/
void* heap_malloc(size_t size)
{
    if( heap_validate() ) return NULL;

    if(size < 1) return NULL;

    void *wsk;

    //
    // CASE 1:
    //
    if( manager.first_memory_chunk == NULL )
    {
        wsk=custom_sbrk(size + blok + 2*plot);
        if(wsk==(void*)-1)
            return NULL;

        manager.first_memory_chunk = (struct memory_chunk_t *)manager.memory_start;
        manager.first_memory_chunk->size = size;
        manager.first_memory_chunk->free = 0;
        manager.first_memory_chunk->prev = NULL;
        manager.first_memory_chunk->next = NULL;

        plotki( (void *)( (uint8_t *)manager.first_memory_chunk + blok),size);

        return (void *)( (uint8_t *)manager.first_memory_chunk + blok + plot);
    }

    //
    // CASE 2:
    //
    struct memory_chunk_t *pcurrent;
    for (pcurrent = manager.first_memory_chunk; pcurrent->next != NULL; pcurrent = pcurrent->next)
    {
        if( pcurrent->size >= size+(2*plot) && pcurrent->free==1)
        {
            pcurrent->free=0;
            pcurrent->size=size;

            plotki((void *)( (uint8_t *)pcurrent + blok),size);

            return (void *)( (uint8_t *)pcurrent + blok +plot);
        }

    }
    if( pcurrent->size >= size+(2*plot) && pcurrent->free==1)
    {
        pcurrent->free=0;
        pcurrent->size=size;

        plotki((void *)( (uint8_t *)pcurrent + blok),size);

        return (void *)( (uint8_t *)pcurrent + blok +plot);
    }

    //
    //CASE 3:
    //
    wsk = custom_sbrk(size + blok + 2*plot);
    if( wsk == (void*)-1 )
    {
        return NULL;
    }

    struct memory_chunk_t *ptr=(struct memory_chunk_t *)( (uint8_t *)pcurrent + pcurrent->size + sizeof(struct memory_chunk_t) + 2*plot );
    ptr->size=size;
    ptr->prev=pcurrent;
    ptr->next=NULL;
    ptr->free=0;
    pcurrent->next=ptr;

    plotki((void *)( (uint8_t *)ptr + blok),size);

    return (void *)( (uint8_t *)ptr + blok +plot);
}



/****/ /****/ /****/
void* heap_calloc(size_t number, size_t size)
{
    void *ptr=heap_malloc(size*number);
    if(ptr==NULL) return NULL;

    memset(ptr,'\0',size*number);

    return ptr;
}



/****/ /****/ /****/
void* heap_realloc(void* memblock, size_t size)
{
    if( heap_validate() ) return NULL;

    if(size == 0)
    {
        heap_free(memblock);
        return NULL;
    }

    if(memblock == NULL)
        return heap_malloc(size);

    if(get_pointer_type(memblock)!=pointer_valid)
        return NULL;

    struct memory_chunk_t *ptr=(struct memory_chunk_t *)( (uint8_t *)memblock - blok - plot);

    size_t rsize = ptr->size;

    if( ptr->next != NULL)
        rsize = (uint8_t *)ptr->next - (uint8_t *)ptr - blok -2*plot;


    if(ptr->size == size)
        return memblock;

    if(size < ptr->size)
    {
        if( ptr ->next == NULL)
            custom_sbrk( -( ptr->size - size));


        ptr->size=size;
        plotki((uint8_t *)ptr+blok,size);

        return memblock;
    }

    if(ptr->next == NULL)
    {
        if(custom_sbrk(size - ptr->size) == (void*)-1)
            return NULL;

        ptr->size = size;
        plotki( (uint8_t *)ptr+blok,size);

        return memblock;
    }

    if( ptr->next->free && (uint8_t*)ptr->next - (uint8_t*)ptr - plot*2 + ptr->next->size>=size)
    {
        ptr->size=size;
        ptr->next=ptr->next->next;
        ptr->next->prev=ptr;

        plotki( (uint8_t *)ptr+blok,size);
        return memblock;
    }

    if( ptr->next->free == 1 && (ptr->next->size + rsize >= size -2*plot*blok) )
    {
        struct memory_chunk_t *n = (struct memory_chunk_t *)( (uint8_t *)ptr->next + size - rsize);
        memmove(n,ptr->next,blok);

        ptr->next = n;
        n->next->prev = n;
        (n->size) -= size - rsize;

        ptr->size = size;
        plotki((uint8_t *)ptr+blok,size);
        return memblock;
    }


    if( ptr->next->free && ptr->next->size >= size)
    {
        struct memory_chunk_t *n = (struct memory_chunk_t *)( (uint8_t *)ptr->next + size);
        memmove(n,ptr->next,blok);

        ptr->next = n;
        n->next->prev = n;
        n->size -= size;

        ptr->size = size;
        plotki((uint8_t *)ptr+blok,size);
        return memblock;
    }

        struct memory_chunk_t *nowa = heap_malloc(size);
        if (!nowa)
            return NULL;

        memcpy(nowa, memblock, ptr->size);
        heap_free(memblock);

        return nowa;

}



/****/ /****/ /****/
void  heap_free(void* memblock)
{
    if( heap_validate() ) return;

    if(memblock==NULL) return;

    struct memory_chunk_t *pcurrent;

    for (pcurrent = manager.first_memory_chunk; pcurrent != (struct memory_chunk_t*)( (uint8_t *)memblock - blok - plot ); pcurrent = pcurrent->next)
    {
        if(pcurrent==NULL) return;
    }

    if(pcurrent->free==1) return;

    pcurrent->free=1;

    //
    // CASE 1:
    //
    if(pcurrent->prev)
        if(pcurrent->prev->free==1)
        {
            pcurrent->prev->size+=pcurrent->size+ blok + 2*plot;
            pcurrent->prev->next=pcurrent->next;

            if( pcurrent->next )
                pcurrent->next->prev=pcurrent->prev;


            pcurrent=pcurrent->prev;
        }

    //
    // CASE 2:
    //
    if(pcurrent->next)
        if(pcurrent->next->free==1)
        {
            pcurrent->size+=pcurrent->next->size+ blok + 2*plot;

            if( pcurrent->next->next )
                pcurrent->next->next->prev=pcurrent;

            pcurrent->next=pcurrent->next->next;
        }

    //
    // CASE 3:
    //
    if(pcurrent->next==NULL && pcurrent->prev==NULL)
    {
        uint8_t *wsk = custom_sbrk(0);

        custom_sbrk( - (wsk - (uint8_t *)manager.memory_start) );
        manager.first_memory_chunk=NULL;

    }
    else pcurrent->size=(uint8_t *)pcurrent->next - (uint8_t *)pcurrent - blok;


    if(pcurrent->next==NULL && pcurrent->prev!=NULL)
    {
        pcurrent->prev->next=NULL;

        uint8_t *wsk = custom_sbrk(0);
        custom_sbrk( - (wsk - (uint8_t *)pcurrent->prev - blok -2*plot - pcurrent->prev->size));


    }

    return;
}



/****/ /****/ /****/
enum pointer_type_t get_pointer_type(const void* const pointer)
{
    if(pointer==NULL) return pointer_null;

    if( heap_validate() ) return pointer_heap_corrupted;


    struct memory_chunk_t *pcurrent=manager.first_memory_chunk;
    uint8_t *ptr=(uint8_t *)pointer;

    while(pcurrent!=NULL)
    {
        uint8_t *start=(uint8_t *)pcurrent;
        uint8_t *u_start=(uint8_t *)pcurrent+blok+plot;
        uint8_t *u_end=(uint8_t *)pcurrent+pcurrent->size+blok+plot;
        uint8_t *f_end=(uint8_t *)pcurrent+pcurrent->size+blok;

        if( pcurrent->free )
            if( ptr >= start+blok && ptr <= f_end )
                return pointer_unallocated;

        if( ptr >= start)
        {
            if(ptr < start+blok) return pointer_control_block;
            else if( (ptr >= start+blok && ptr < u_start) || (ptr>=u_end && ptr < u_end+plot) ) return pointer_inside_fences;
            else if( ptr > u_start && ptr <= u_end) return pointer_inside_data_block;
            else if( ptr==u_start) return pointer_valid;
        }
        if( ptr > (uint8_t *)custom_sbrk(0))
            return pointer_unallocated;

        pcurrent = pcurrent->next;
    }

    return pointer_unallocated;
}



/****/ /****/ /****/
int heap_validate(void)
{
    if(manager.memory_start == NULL)
        return 2;

    struct memory_chunk_t *pcurrent = manager.first_memory_chunk;
    struct memory_chunk_t *koniec = custom_sbrk(0);


    //
    // 1
    //
    if(pcurrent != NULL)
    {
        if(pcurrent->free != 0 && pcurrent->free != 1)
            return 3;

        //if(pcurrent >= koniec)
        //    return 3;

        if(pcurrent->prev != NULL)
            return 3;


        if(pcurrent->free == 1)
        {
            if(pcurrent->next == NULL)
                return 3;

            //if( pcurrent->size + blok > (unsigned long)( (uint8_t*)pcurrent->next - (uint8_t*)pcurrent ) )
            //    return 3;
        }
        else
        {
            //if( pcurrent->size + blok + 2*plot > (unsigned long)( (uint8_t*)pcurrent->next - (uint8_t*)pcurrent ) )
             //   return 3;
            if( pcurrent->size == 0)
                return 3;
        }

        if( pcurrent->next != NULL )
        {
            if(pcurrent->next >= koniec || pcurrent->next < pcurrent)
                return 3;
            if(pcurrent->next->prev != pcurrent)
                return 3;

            pcurrent = pcurrent->next;
        }
    }

    //
    // 2
    //
    while(pcurrent != NULL && pcurrent->next != NULL)
    {
        if(pcurrent->free != 1 && pcurrent->free != 0)
            return 3;

        //if(pcurrent >= koniec)
        //    return 3;


        if(pcurrent->free == 1)
        {
            if( pcurrent->size + blok > (unsigned long)( (uint8_t*)pcurrent->next - (uint8_t*)pcurrent ))
                return 3;
        }
        else
        {
            //if( pcurrent->size + blok+2*plot > (unsigned long)( (uint8_t*)pcurrent->next - (uint8_t*)pcurrent ))
             //   return 3;
            if( pcurrent->size == 0)
                return 3;
        }

        if( pcurrent->next != NULL )
        {
            if( pcurrent->next >= koniec || pcurrent->next < pcurrent)
                return 3;
            if( pcurrent->next->prev != pcurrent )
                return 3;

            pcurrent = pcurrent->next;
        }
    }

    //
    // 3
    //
    if(pcurrent != NULL)
    {
        if( pcurrent->free != 0)
            return 3;
        if( (uint8_t*)pcurrent + blok + 2*plot + pcurrent->size > (uint8_t*)koniec)
            return 3;
    }




    for (pcurrent = manager.first_memory_chunk; pcurrent != NULL; pcurrent = pcurrent->next)
    {
        if(pcurrent->free == 1) continue;

        unsigned char *pom=(unsigned char *)pcurrent;

        pom+=blok;

        for(int j=0;j<plot;j++)
        {
            if( *(pom+j)!='#') return 1;
        }
        pom+=plot;
        pom+=pcurrent->size;

        for(int j=0;j<plot;j++)
        {
            if( *(pom+j)!='#') return 1;
        }

    }
    return 0;
}



/****/ /****/ /****/
void* heap_malloc_aligned(size_t size)
{
    if( heap_validate() ) return NULL;

    if(size < 1) return NULL;

    void *wsk;

    //
    // CASE 1:
    //

    if( manager.first_memory_chunk == NULL )
    {
        wsk=custom_sbrk(PAGE_SIZE + plot + size);
        if(wsk==(void*)-1)
            return NULL;

        manager.first_memory_chunk = (struct memory_chunk_t *)( (uint8_t *)wsk + PAGE_SIZE - blok - plot);
        manager.first_memory_chunk->size = size;
        manager.first_memory_chunk->free = 0;
        manager.first_memory_chunk->prev = NULL;
        manager.first_memory_chunk->next = NULL;

        plotki( (void *)( (uint8_t *)manager.first_memory_chunk + blok),size);

        return (void *)( (uint8_t *)manager.first_memory_chunk + blok + plot);
    }

    
    //
    // CASE 2:
    //
    struct memory_chunk_t *pcurrent;
    for (pcurrent = manager.first_memory_chunk; pcurrent->next != NULL; pcurrent = pcurrent->next)
    {
        uint8_t *ptr=((uint8_t *)pcurrent+plot+blok);

        if( pcurrent->size >= size+(2*plot) && pcurrent->free==1 && ((intptr_t)ptr & (intptr_t)(PAGE_SIZE - 1)) == 0)
        {
            pcurrent->free=0;
            pcurrent->size=size;

            plotki((void *)( (uint8_t *)pcurrent + blok),size);

            return (void *)( (uint8_t *)pcurrent + blok +plot);
        }

    }
    uint8_t *ptr1=((uint8_t *)pcurrent+plot+blok);
    if( pcurrent->size >= size+(2*plot) && pcurrent->free==1 && ((intptr_t)ptr1 & (intptr_t)(PAGE_SIZE - 1)) == 0)
    {
        
        pcurrent->free=0;
        pcurrent->size=size;

        plotki((void *)( (uint8_t *)pcurrent + blok),size);

        return (void *)( (uint8_t *)pcurrent + blok +plot);
    }

    //
    //CASE 3:
    //
    uint8_t *koniec = custom_sbrk(0);

    intptr_t i=0;

    while(1)
    {
        if(((intptr_t)koniec+i & (intptr_t)(PAGE_SIZE - 1)) == 0 && (unsigned int)i>=blok+plot)
            break;

        i++;
    }

    wsk = custom_sbrk(plot + size+i);
    if(wsk == (void*)-1)
        return NULL;

    struct memory_chunk_t *ptr=(struct memory_chunk_t*)( (uint8_t*)custom_sbrk(0)- 2*plot-size-blok);
    ptr->size=size;
    ptr->prev=pcurrent;
    ptr->next=NULL;
    ptr->free=0;
    pcurrent->next=ptr;

    plotki((void *)( (uint8_t *)ptr + blok),size);

    return (void *)( (uint8_t *)ptr + blok +plot);
}



/****/ /****/ /****/
void* heap_calloc_aligned(size_t number, size_t size)
{
    void *ptr=heap_malloc_aligned(size*number);
    if(ptr==NULL) return NULL;

    memset(ptr,'\0',size*number);

    return ptr;
}



/****/ /****/ /****/
void* heap_realloc_aligned(void* memblock, size_t size)
{
    if( heap_validate() ) return NULL;

    if(size == 0)
    {
        heap_free(memblock);
        return NULL;
    }


    if(memblock == NULL)
        return heap_malloc_aligned(size);

    if( ((intptr_t)memblock & (intptr_t)(PAGE_SIZE - 1)) != 0)
        return NULL;

    if(get_pointer_type(memblock)!=pointer_valid)
        return NULL;


    struct memory_chunk_t *ptr=(struct memory_chunk_t *)( (uint8_t *)memblock - blok - plot);

    size_t rsize = ptr->size;

    if( ptr->next != NULL)
        rsize = (uint8_t *)ptr->next - (uint8_t *)ptr - blok -2*plot;


    if(ptr->size == size)
        return memblock;

    if(size < ptr->size)
    {
        if( ptr ->next == NULL)
            custom_sbrk( - (ptr->size - size));


        ptr->size=size;
        plotki((uint8_t *)ptr+blok,size);

        return memblock;
    }

    if(ptr->next == NULL)
    {
        if(custom_sbrk(size - ptr->size) == (void*)-1)
            return NULL;

        ptr->size = size;
        plotki( (uint8_t *)ptr+blok,size);

        return memblock;
    }

    if( ptr->next->free && (uint8_t*)ptr->next - (uint8_t*)ptr - plot*2 + ptr->next->size>=size)
    {
        ptr->size=size;
        ptr->next=ptr->next->next;
        ptr->next->prev=ptr;

        plotki( (uint8_t *)ptr+blok,size);
        return memblock;
    }

    if( (rsize >= size -2*plot*blok) )
    {
        ptr->size = size;
        plotki( (uint8_t *)ptr+blok,size);
        return memblock;
    }

    if( ptr->next->free == 1 && (ptr->next->size + rsize >= size -2*plot*blok) )
    {
        struct memory_chunk_t *n = (struct memory_chunk_t *)( (uint8_t *)ptr->next + size - rsize);
        memmove(n,ptr->next,blok);

        ptr->next = n;
        n->next->prev = n;
        (n->size) -= size - rsize;

        ptr->size = size;
        plotki((uint8_t *)ptr+blok,size);
        return memblock;
    }


    if( ptr->next->free && ptr->next->size >= size)
    {
        struct memory_chunk_t *n = (struct memory_chunk_t *)( (uint8_t *)ptr->next + size);
        memmove(n,ptr->next,blok);

        ptr->next = n;
        n->next->prev = n;
        n->size -= size;

        ptr->size = size;
        plotki((uint8_t *)ptr+blok,size);
        return memblock;
    }

    struct memory_chunk_t *nowa = heap_malloc_aligned(size);
    if (!nowa)
        return NULL;

    memcpy(nowa, memblock, ptr->size);
    heap_free(memblock);

    return nowa;

}
/* the end :P */

