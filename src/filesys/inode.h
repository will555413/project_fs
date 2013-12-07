#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct bitmap;

#define DIRECT_ENTRIES 123
#define INDEX_BLOCK_ENTRIES 128
#define DOUBLY_INDIRECT_ENTRIES 16384

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t data_sectors[DIRECT_ENTRIES];   /* Data sectors */
    block_sector_t index_1;             /* Sector number of indirect index */
    block_sector_t index_2;             /* Sector number of doubly indirect index */
    off_t length;                       /* File size in bytes. */
    int is_directory;
    block_sector_t parent_dir;
  };

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Disk location represented by sector number. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock write_extend_lock;
    struct condition write_extend_condition;
    struct inode_disk data;             /* Inode content. */
  };

void inode_init (void);
bool inode_create (block_sector_t, off_t, bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

#endif /* filesys/inode.h */
