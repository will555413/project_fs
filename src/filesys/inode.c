#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#define INDEX_BLOCK_ENTRIES 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t data_sectors[125];   /* Data sectors */
    block_sector_t index_1;             /* Sector number of indirect index */
    block_sector_t index_2;             /* Sector number of doubly indirect index */
    off_t length;                       /* File size in bytes. */
  };

/* On-disk index, should probably be BLOCK_SECTOR_SIZE bytes long. */
struct index_block
{
  block_sector_t sectors[128];          /* Array of sectors */
};

static int debug_fs = 0;
static int verbose_fs = 0;

static struct lock extend_lock;

static block_sector_t logical_to_physical_idx(struct inode *inode, block_sector_t logical_idx);
static bool extend_inode(struct inode *inode, off_t size, off_t offset);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Disk location represented by sector number. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

static block_sector_t block_id_to_sector(struct inode *inode, block_sector_t block_id)
{
  struct index_block *idx_buf;
  /* sectors 0 to 124 are pointed to directly */
  if (block_id < 125)
  {
    return inode->data.data_sectors[block_id];
  }

  /* 'advance' our block_id so that we are now 
      at the first index of this level of indirection */
  block_id -= 125;
  /* sectors 125 to 252 are pointed to indirectly */
  if (block_id < 128)
  {
    block_sector_t idx1 = inode->data.index_1;
    if (idx1 == NULL) 
      return NULL;

    /* read disk at sector idx1 into a temporary buffer */
    idx_buf = malloc(sizeof(struct index_block));
    block_read(fs_device, idx1, idx_buf);
    block_sector_t physical_sector = idx_buf->sectors[block_id];
    
    /* cleanup and return */
    free(idx_buf);
    return physical_sector;
  }

  /* 'advance' our block_id again */
  block_id -= 128;
  /* sectors 253 to 16383 are at two levels of indirection.
      We don't point above 16383 because that would exceed 8 MB */
  if (block_id < 16384)
  {
    block_sector_t idx2 = inode->data.index_2;
    if (idx2 == NULL)
      return NULL;

    block_sector_t idx1 = block_id / INDEX_BLOCK_ENTRIES;
    int idx_offset = block_id % INDEX_BLOCK_ENTRIES;

    /* read disk at sector idx2 into a temporary buffer */
    idx_buf = malloc(sizeof(struct index_block));
    block_read(fs_device, idx2, idx_buf);

    /* get physical sector of next index_block then read from that to the buffer */
    block_sector_t physical_idx1_sector = idx_buf->sectors[idx1];
    if (physical_idx1_sector ==  NULL)
      return NULL;

    block_read(fs_device, physical_idx1_sector, idx_buf);
    block_sector_t physical_sector = idx_buf->sectors[idx_offset];

    /* cleanup and return */
    free(idx_buf);
    return physical_sector;
  }

  else
    PANIC("Bad logical sector provided, must be between 0 and 16383.");

  return NULL; /* Shouldn't be reached */
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return inode->data.data_sectors[0] + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  if (verbose_fs) printf("inode_init()\n");
  list_init (&open_inodes);
  lock_init(&extend_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  if (verbose_fs) printf("inode_create(): inumber = %d, length = %d\n", sector, length);
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {

      /* Initiate data_sectors array and indirect block addresses */
      block_sector_t s;
      for (s = 0; s < 125; s++)
        disk_inode->data_sectors[s] = -1;
      disk_inode->index_1 = -1;
      disk_inode->index_2 = -1;




      size_t sectors = bytes_to_sectors (length);
      //if (debug_fs) printf("sectors = %d\n", sectors);
      disk_inode->length = length;
      //disk_inode->magic = INODE_MAGIC;
      block_sector_t *sector_pointer; 
      free_map_allocate (1, sector_pointer);
      block_sector_t first_sector = *sector_pointer;
      disk_inode->data_sectors[0] = first_sector;

      int i;
      for (i = 1; i < sectors; i++)
      {
        free_map_allocate (1, &disk_inode->data_sectors[i]);
        //disk_inode->data_sectors[i] = *sector_pointer;
        if (verbose_fs) printf("\t\tdisk_inode->data_sectors[0] = %d\n", disk_inode->data_sectors[0]);
        //if (debug_fs) printf("data_sectors[%d] = %d\n", i, *sector_pointer);
      }

      if (verbose_fs) printf("\tbefore write disk_inode->data_sectors[0] = %d\n", disk_inode->data_sectors[0]);
      block_write (fs_device, sector, disk_inode);
      // if (free_map_allocate (sectors, sector_pointer)) 
      //   {
      //     disk_inode->data_sectors[0] = *sector_pointer;
      //     block_write (fs_device, sector, disk_inode);
      //     if (sectors > 0) 
      //       {
      //         static char zeros[BLOCK_SECTOR_SIZE];
      //         size_t i;
              
      //         for (i = 0; i < sectors; i++)
      //         {
      //           if (i != 0)
      //             disk_inode->data_sectors[i] = disk_inode->data_sectors[0] + i;
      //           if (debug_fs) printf("data_sectors[%d] = %d\n", i, disk_inode->data_sectors[0] + i);
      //           block_write (fs_device, disk_inode->data_sectors[i], zeros);
      //         }
      //       }
      //     success = true; 
      //   } 
      success = true;
      free (disk_inode);
      
      if (verbose_fs)
      {
        printf("\tverifying inode creation...\n");
        struct inode_disk *verify_inode = calloc (1, sizeof *verify_inode);
        block_read(fs_device, sector, verify_inode);
        printf("\tverify_inode->data_sectors[0] = %d\n", verify_inode->data_sectors[0]);
        free(verify_inode);
      }
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  if (verbose_fs) printf("inode_open(): inumber = %d\n", sector);
  
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  if (debug_fs) printf("\tinode->data.data_sectors[0] = %d\n", inode->data.data_sectors[0]);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  //if (debug_fs) printf("inode_close(): inode->sector = %d\n", inode->sector);
  //if (debug_fs) printf("\tinode->data.data_sectors[0] = %d\n", inode->data.data_sectors[0]);
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Write to disk */
      block_write(fs_device, inode->sector, &inode->data);

      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          if (debug_fs) printf("\tinode was marked as removed, deallocating sectors...\n");
          free_map_release (inode->sector, 1);
          int i = 0;
          while (inode->data.data_sectors[i] != -1)
          {
            free_map_release (inode->data.data_sectors[i], 1);
            i++; 
          }
          
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  //if (debug_fs) printf("inode_read_at(): inode_number = %d, file_length = %d\n", inode->sector, inode->data.length);
  //if (debug_fs) printf("inode_read_at(): read_size = %d, offset = %d\n", size, offset);
  //if (debug_fs) printf("\tinode->data.data_sectors[0] = %d\n", inode->data.data_sectors[0]);

  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* TEMPORARY */
      if (bytes_to_sectors(offset) > 124)
        PANIC("TEMPORARY - ONLY GROWING UP TO 125 SECTORS FOR NOW");
      /* TEMPORARY */

      /* Disk sector to read, starting byte offset within sector. */
      //block_sector_t sector_idx = byte_to_sector (inode, offset);
      block_sector_t block_id = offset/BLOCK_SECTOR_SIZE;
      //if (debug_fs) printf("block_id = %d\n", block_id);
      
      block_sector_t sector_idx = block_id_to_sector(inode, block_id);
      //if (debug_fs) printf("sector_idx = %d\n", sector_idx);
      if (inode->sector != 0 && sector_idx == 0)
        PANIC("ERMAGER");
      if (sector_idx > 4*4096)
        PANIC("Got bad sector id for inode data table");

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      //if (debug_fs) printf("sector_ofs = %d\n", sector_ofs);
      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      //if (debug_fs) printf("inode_left = %d\n", inode_left);
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      //if (debug_fs) printf("sector_left = %d\n", sector_left);
      int min_left = inode_left < sector_left ? inode_left : sector_left;
      //if (debug_fs) printf("min_left = %d\n", min_left);
      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      //if (debug_fs) printf("chunk_size = %d\n", chunk_size);
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  //if (debug_fs) printf("inode_write_at(): inode_number = %d, file_length = %d\n", inode->sector, inode->data.length);
  //if (debug_fs) printf("inode_write_at(): write_size = %d, offset = %d\n", size, offset);
  //if (debug_fs) printf("\tinode->data.data_sectors[0] = %d\n", inode->data.data_sectors[0]);

  if (inode->data.length < offset + size)
  {
    extend_inode(inode, size, offset);
  }

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) 
    {
      /* TEMPORARY */
      if (bytes_to_sectors(offset) > 124)
        PANIC("TEMPORARY - ONLY GROWING UP TO 125 SECTORS FOR NOW");
      /* TEMPORARY */

      /* Sector to write, starting byte offset within sector. */
      //block_sector_t sector_idx = byte_to_sector (inode, offset);
      block_sector_t block_id = offset/BLOCK_SECTOR_SIZE;
      //if (debug_fs) printf("block_id = %d\n", block_id);

      block_sector_t sector_idx = block_id_to_sector(inode, block_id);
      if (debug_fs) printf("sector_idx = inode->data.data_sectors[%d] = %d\n", block_id, sector_idx);

      if (inode->sector != 0 && sector_idx == 0)
        PANIC("ERMAGER");
      if (sector_idx > 4*4096)
        PANIC("Got bad sector id for inode data table");

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      //off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      //int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* makes sure that at least 'sectors' are allocated to the direct array */
static void allocate_direct(struct inode *inode, block_sector_t sectors)
{
  ASSERT(sectors <= 125)
  int i;
  for (i = 0; i < sectors; i++)
  {
    if (inode->data.data_sectors[i] == -1)
      free_map_allocate(1, &inode->data.data_sectors[i]);
  }
}

/* Makes sure that the indirect block is allocated, and all entries up to 'sectors' are allocated */
static void allocate_indirect(struct inode *inode, block_sector_t sectors)
{
  ASSERT(sectors <= 128)
  struct index_block *indirect_block;
  if (inode->data.index_1 == -1)
  {
    indirect_block = calloc(1, sizeof *indirect_block);
    free_map_allocate(1, &inode->data.index_1);
  }
  else
    block_read(fs_device, inode->data.index_1, indirect_block);

  int i;
  for (i = 0; i < sectors; i++)
  {
    if (indirect_block->sectors[i] == -1)
      free_map_allocate(1, &indirect_block->sectors[i]);
  }

  block_write(fs_device, inode->data.index_1, indirect_block);
  free(indirect_block);
}

static bool extend_inode(struct inode *inode, off_t size, off_t offset)
{
  if (debug_fs) printf("extend_inode(): inode->sector = %d, size = %d, offset = %d\n", inode->sector, size, offset);
  lock_acquire(&extend_lock);

  /* Case 1: starting before EOF, but writing past it */
  if (offset <= inode->data.length)
  {
    int eof_sector_ofs = inode->data.length % BLOCK_SECTOR_SIZE;
    int eof_sector_left = BLOCK_SECTOR_SIZE - eof_sector_ofs;

    off_t bytes_needed = (offset + size) - inode->data.length;
    off_t sectors_needed;
    off_t sectors_grown = 0;

    if (bytes_needed - eof_sector_left <= 0)
      sectors_needed = 0;
    else
      sectors_needed = bytes_to_sectors(bytes_needed - eof_sector_left);

    block_sector_t eof_block_id = bytes_to_sectors(inode->data.length);
    int i;

    int new_eof = eof_block_id + sectors_needed;
    if (new_eof <= 124)
      allocate_direct(inode, new_eof);
    else if (new_eof <= 252)
      allocate_indirect(inode, new_eof);
    else
      PANIC("NOT IMPLEMTEND YET GO AWAY");
    // block_sector_t *sector_pointer;

    // if (eof_block_id < 124)
    // {
    //   for (i = 0; i < sectors_needed; i++)
    //   {
    //     free_map_allocate(1, sector_pointer);
    //     inode->data.data_sectors[eof_block_id + 1 + i] = *sector_pointer;
    //     sectors_grown++;
    //     if ((eof_block_id + 1 + i) = 124)
    //     {
    //       sectors_needed -= sectors_grown;
    //       break;
    //     }
    //   }
    //   eof_block_id += sectors_grown;
    // }
    //block_sector_t eof_sector = block_id_to_sector(eof_block_id);
    inode->data.length += bytes_needed;
  }

  /* Case 2: starting after EOF */
  else
  {
    printf("case 2\n");
  }

  lock_release(&extend_lock);
  return true;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
