#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "devices/block.h"
#include "devices/shutdown.h"
#include "devices/timer.h"

static void syscall_handler (struct intr_frame *);
static int is_valid_pointer(int *uaddr);

int debug_fs = 0;

static block_sector_t temp_dir_inumber = 1;

// static void get_file_list(char *filepath, char **file_list)
// {
//   char *token, *save_ptr;
//   int num_files = 0;

//   for (token = strtok_r (filepath, "/", &save_ptr);
//         token != NULL;
//         token = strtok_r (NULL, "/", &save_ptr))
//   {
//       file_list[num_files] = token;
//       num_files++;
//   }
// }

static struct inode *get_last_inode(char *dirline, char *last_file)
{
  //if (debug_fs) printf("\tget_last_inode(): dirline = %s, cur_dir_inode = %d @ %p\n", dirline, current_dir->inode->sector, current_dir);
  
  /* Check for absolute or relative */
  bool absolute = (dirline[0] == '/');

  /* Set the sector of the current working directory */
  struct thread *t = thread_current();
  block_sector_t cd_sector = t->current_directory;
  if (absolute)
    cd_sector = 1;

  /* Make a copy of the dirline argument provided by the user so that we don't modify
      their memory */
  char *dirline_cpy;
  dirline_cpy = palloc_get_page(0);
  if (dirline_cpy == NULL)
    return TID_ERROR;
  strlcpy(dirline_cpy, dirline, PGSIZE);

  char *save_ptr, *token;
  struct inode *inode;
  struct inode *temp_inode;
  struct dir *current_dir;
  struct dir *next_dir = NULL;
  for (token = strtok_r(dirline_cpy, "/", &save_ptr);
        token != NULL;
        token = strtok_r(NULL, "/", &save_ptr))
  {
    strlcpy(last_file, token, strlen(token)+1);
    if (debug_fs) printf("\t\ttoken = %s\n", token);
    //struct inode *cur_dir_inode = dir_get_inode(current_dir);
    //if (debug_fs) printf("\t\t current_dir_inumber = %s\n", cur_dir_inode->sector);
    if(strcmp(token, ".") == 0)
    {
      if (debug_fs) printf("\t\tdetected \".\", continuing\n");
      continue;
    }

    if(strcmp(token, "..") == 0)
    {
      if (debug_fs) printf("\t\tdetected \"..\", going up a level\n");
      temp_inode = inode_open(cd_sector);
      cd_sector = temp_inode->data.parent_dir;
      continue;
    }

    if(strlen(token)>14)
    {
      if(debug_fs) printf("\t\tDirectory name is too long\n");
      inode = NULL;
      break;
    }

    temp_inode = inode_open(cd_sector);
    current_dir = dir_open(temp_inode);
    if (debug_fs) printf("\t\ttrying to lookup '%s' in the dir = %d @ %p\n", token, current_dir->inode->sector, current_dir);

    if(dir_lookup(current_dir, token, &inode))
    {
      if(debug_fs) printf("\t\tFound %s in current directory\n", token);
      if (inode->removed)
      {
        inode = NULL;
        break;
      }
      else if(inode->data.is_directory)
      {
        next_dir = dir_open(inode);
        cd_sector = next_dir->inode->sector;
        //dir_close(current_dir);
        current_dir = next_dir;
        if (debug_fs) printf("\t\tchanged current dir inumber to %d and dir @ %p\n", current_dir->inode->sector, current_dir);
      }
      //else
        //dir_close(current_dir);
    }
    else
    {
      //dir_close(current_dir);
      inode = NULL;
      break;
    }
  }

  //if (debug_fs) printf("\t\tcurrent dir inumber = %d and dir @ %p\n", current_dir->inode->sector, current_dir);
  temp_dir_inumber = cd_sector;
  if (debug_fs) printf("\t\ttemp_dir_inumber = %d\n", temp_dir_inumber);

  palloc_free_page(dirline_cpy);
  return inode;
}

// /* Find the last file provide in dirline and copy it to
//   last_file, then return the length of last_file */
// static int get_last_file(char *dirline, char *last_file)
// {
//   int dirline_length = strlen(dirline) + 1;
//   char *dirline_cpy = calloc(dirline_length, sizeof(char));
//   strlcpy(dirline_cpy, dirline, dirline_length);
//   char *save_ptr, *token, *prev_token;
//   if (debug_fs) printf("get_last_file(): dirline_cpy = %s at %p\n", dirline_cpy, dirline_cpy);
//   for (token = strtok_r(dirline_cpy, "/", &save_ptr);
//       token != NULL;
//       token = strtok_r(NULL, "/", &save_ptr))
//   {
//     // if (debug_fs) printf("\ttoken = %s at %p\n", token, *token);
//     // if (debug_fs) printf("\tsave_ptr = %s at %p\n", (char*)save_ptr, (char**)save_ptr);
//     prev_token = token;
//   }
//   // if (debug_fs) printf("\tdone tokenizing\n");
//   // if (debug_fs) printf("\ttoken = %s at %p\n", token, *token);
//   // if (debug_fs) printf("\tprev_token = %s at %p\n", prev_token, *prev_token);
//   strlcpy(last_file, prev_token, strlen(prev_token));
//   free(dirline_cpy);
//   return strlen(last_file);
// }

// /* Removes last file from dirline and returns inode of the
//     new last file */
// static bool chop_dirline(char *dirline, struct inode *inode, char *last_file)
// {
//   struct thread *t = thread_current ();
//   struct inode *cur_dir_inode;
//   int str_idx;
//   char file_name[15];

//   /* Open inode of this thread's working directory */
//   cur_dir_inode = inode_open(t->current_directory);

//   /* Find index of the '/' before the last file and set to null */
//   str_idx = strlen(dirline) - get_last_file(dirline, last_file) - 1;
//   dirline[str_idx] = '\0';
//   //printf("setting dirline[%d] = null\n", str_idx);
//   /* Search current directory (or root) for the new last file,
//       and set the provided inode to it's inode */
//   inode = get_last_inode(dirline, cur_dir_inode, last_file);
//   //printf("\tgot last inode\n");
//   inode_close(cur_dir_inode);
//   return true;
// }

int is_valid_pointer(int *uaddr)
{
  if (is_kernel_vaddr(uaddr))
    return 0;
  /* else user vaddr, now have to check pages */
  uintptr_t p_pd;
  uintptr_t *v_pd;
  asm volatile ("movl %%cr3, %0" : "=r" (p_pd));
  v_pd = ptov(p_pd);
  void *page = pagedir_get_page(v_pd, uaddr);
  if (page == NULL)
    return 0;
  return 1;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  struct thread *t = thread_current();
  struct file *file_ptr;
  struct dir *dir;
  struct inode *inode;
  struct inode *temp_inode;

  bool success = false;
  char last_file[15];
  char temp_fn[15];
  block_sector_t new_file_sector = -1;

  int fd = 2;
  int *syscall_num_ptr = f->esp;

  if (is_valid_pointer(syscall_num_ptr) == 0 || f->esp >= (PHYS_BASE - 4))
  {
    thread_exit();
  }

  char *buf;
  int *arg0 = f->esp+4;
  int *arg1 = f->esp+8;
  int *arg2 = f->esp+12;
  int *arg_array[3];
  arg_array[0] = arg0;
  arg_array[1] = arg1;
  arg_array[2] = arg2;

  int valid_array[3];

  int i;
  for (i = 0; i < 3; i++)
  {
    valid_array[i] = is_valid_pointer(*arg_array[i]);
  }

  // char *dirline = calloc(1, strlen(*arg0));
  // strlcpy(dirline, *arg0, strlen(*arg0));
  // char *token;
  // char *save_ptr;
  // struct inode *current_dir_inode = inode_open(t->current_directory);
  // void *dir = dir_open(current_dir_inode);
  // struct inode **inode;

  switch (*syscall_num_ptr)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;

  	case SYS_EXIT:
  		t->exit_status = *arg0;
  		thread_exit();
  		break;

    case SYS_EXEC:
      if (valid_array[0] != 1)
      {
        thread_exit();
      }

      tid_t ret_val = NULL;
      ret_val = process_execute((char*)*arg0);
      sema_down(&t->load_wait_sema);
      if (t->load_wait_status == 0)
      {
        f->eax = -1;
        break;
      }
      t->load_wait_status = 0;
      f->eax = ret_val;
      break;

    case SYS_WAIT:
      f->eax = process_wait(*arg0);
      break;

  	case SYS_CREATE:
      if (valid_array[0] != 1)
      {
        thread_exit();
      }
  		if (strlen((char*)*arg0) > 14 || strlen((char*)*arg0) < 1)
  		{
  			f->eax = 0;
  			break;
  		}
      //   sema_down(t->filesys_sema_ptr);
    	//   f->eax = filesys_create((char*)*arg0, *arg1);
      //   sema_up(t->filesys_sema_ptr);
      if (debug_fs) printf("\tSYS_CREATE:\n");

      temp_inode = inode_open(t->current_directory);
      if (arg0[0] != '/' && temp_inode->removed)
      {
        f->eax = 0;
        break;
      }
      // if (debug_fs) printf("\tcurrent dir inumber = %d\n", t->current_directory);
      dir = dir_open(temp_inode);
      // if (debug_fs) printf("\t!!!dir address before get_last_inode = %p\n", dir);
      // if (debug_fs) printf("\t!!!dir inumber before get_last_inode = %d\n", dir->inode->sector);
      inode = get_last_inode(*arg0, last_file);
      // if (debug_fs) printf("\t!!!dir address after get_last_inode = %p\n", dir);
      // if (debug_fs) printf("\t!!!dir inumber after get_last_inode = %d\n", dir->inode->sector);
      if (inode != NULL)
      {
        f->eax = false;
        dir_close(dir);
        break;
      }

      dir_close(dir);

      
      free_map_allocate(1, &new_file_sector);
      inode_create(new_file_sector, *arg1, 0);
      temp_inode = inode_open(temp_dir_inumber);
      dir = dir_open(temp_inode);
      /* Add the file as an entry to it's parent directory */
      success = dir_add(dir, last_file, new_file_sector);
      inode = inode_open(new_file_sector);
      inode->data.parent_dir = dir->inode->sector;
      if (debug_fs) printf("inode->data.length = %d\n", inode->data.length);
      inode_close(inode);
      dir_close(dir);

      //printf("\tnew_file_sector = %d\n", new_file_sector);


      f->eax = success;
  		break;

    case SYS_REMOVE:
      if (valid_array[0] != 1)
      {
        thread_exit();
      }

      if (debug_fs) printf("SYS_REMOVE: %s\n", *arg0);
      if (strcmp(*arg0, "/") == 0)
      {
        if (debug_fs) printf("special remove case of '/', fails\n");
        f->eax = 0;
        break;
      }

      else if (strcmp(*arg0, ".") == 0)
      {
        if (debug_fs) printf("special remove case of '.', fails\n");
        f->eax = 0;
        break;
      }

      else if (strcmp(*arg0, "..") == 0)
      {
        if (debug_fs) printf("special open remove of '..', fails\n");
        f->eax = 0;
        break;
      }

      else
      {
        //temp_inode = inode_open(t->current_directory);
        //dir = dir_open(temp_inode);
        inode = get_last_inode(*arg0, last_file);
        //dir_close(dir);

        if (inode == NULL)
        {
          if (debug_fs) printf("\tSYS_REMOVE: inode ==  NULL fail\n");
          f->eax = 0;
          break;
        }
        if (inode->removed || inode->sector == 1)
        {
          if (debug_fs) printf("\tSYS_REMOVE: inode already removed or is rood\n");
          f->eax = 0;
          break;
        }
        if (inode->data.is_directory == true)
        {
          dir = dir_open(inode);
          if (debug_fs) printf("\tSYS_REMOVE: opened directory at inumber = %d\n", inode->sector);
          if (dir_readdir(dir, temp_fn) != false)
          {
            if (debug_fs) printf("\tSYS_REMOVE: trying to remove non-empty dir, (found '%s')\n", temp_fn);
            dir_close(dir);
            f->eax = 0;
            break;
          }         
        }
        temp_inode = inode_open(inode->data.parent_dir);
        dir = dir_open(temp_inode);
        dir_remove(dir, last_file);
        dir_close(dir);
        inode_remove(inode);
      }

      f->eax = 1;
      break;

  	case SYS_OPEN:
      if (valid_array[0] != 1)
      {
        thread_exit();
      }

      if(t->fd_array[127] != NULL || strlen(*arg0) == 0)
      {
        f->eax = -1;
        break;
      }

      if (debug_fs) printf("SYS_OPEN: %s\n", *arg0);
      if (strcmp(*arg0, "/") == 0)
      {
        if (debug_fs) printf("special open case of '/', open root\n");
        inode = inode_open(1);
        file_ptr = file_open(inode);
      }

      else if (strcmp(*arg0, ".") == 0)
      {
        if (debug_fs) printf("special open case of '.', open cwd\n");
        inode = inode_open(t->current_directory);
        if (inode->removed)
        {
          f->eax = -1;
          break;
        }
        file_ptr = file_open(inode);
      }

      else if (strcmp(*arg0, "..") == 0)
      {
        if (debug_fs) printf("special open case of '..', open cwd's parent\n");
        inode = inode_open(t->current_directory);
        if (inode->removed)
        {
          inode_close(inode);
          f->eax = -1;
          break;
        }
        temp_inode = inode_open(inode->data.parent_dir);
        inode_close(inode);
        if (temp_inode->removed)
        {
          inode_close(temp_inode);
          f->eax = -1;
          break;
        }
        file_ptr = file_open(temp_inode);
      }

      else
      {
        temp_inode = inode_open(t->current_directory);
        dir = dir_open(temp_inode);
        inode = get_last_inode(*arg0, last_file);
        dir_close(dir);

        if (inode == NULL)
        {
          f->eax = -1;
          break;
        }

        if (inode->removed)
        {
          f->eax = -1;
          break;
        }
        file_ptr = file_open(inode);
      }

  		if (file_ptr == NULL)
  		{
  			f->eax = -1;
  			break;
  		}

      if (inode->data.is_directory)
      {
        file_ptr->is_dir = true;
        file_ptr->dir_ptr = dir_open(file_ptr->inode);
      }
      else
        file_ptr->is_dir = false;
  		
      //printf("\tfile_ptr->inode->sector = %d\n", file_ptr->inode->sector);
  		fd = 2;
  		while (t->fd_array[fd] != NULL && fd < 128)
  		{
  			fd++;
  		}
      
  		t->fd_array[fd] = file_ptr;
      t->files_opened++;
  		f->eax = fd;
  		break;

    case SYS_FILESIZE:
      if (*arg0 < 2 || *arg0 > 127)
      {
        f->eax = -1;
        break;
      }
      file_ptr = t->fd_array[(int)*arg0];
      // sema_down(t->filesys_sema_ptr);
      // f->eax = file_length(file_ptr);
      // sema_up(t->filesys_sema_ptr);
      if (debug_fs) printf("file_ptr->inode->data.length = %d\n", file_ptr->inode->data.length);
      f->eax = file_ptr->inode->data.length;
      break;

    case SYS_READ:
      if (valid_array[1] != 1)
      {
        thread_exit();
      }
      if((int)*arg0 == 0)
      {
        break;
      }
      if((int)*arg0 == 1 || *arg0 > 127 || *arg0 < 0 || t->fd_array[*arg0] == NULL)
      {
        f->eax = -1;
        break;
      }
      else
      {
        file_ptr = t->fd_array[*arg0];
        // sema_down(t->filesys_sema_ptr);
        // f->eax = file_read(file_ptr, (void*)*arg1, (off_t)*arg2);
        // sema_up(t->filesys_sema_ptr);
        f->eax = file_read(file_ptr, (void*)*arg1, (off_t)*arg2);
      }
      break;

  	case SYS_WRITE:
      if (valid_array[1] != 1)
      {
        thread_exit();
      }
  
      buf = *arg1;

      if (*arg0 <= 0 || *arg0 > 127 || *arg2 < 0)
      {
        f->eax = -1;
        break;
      }
  		if (*arg0 == 1)
  		{
  			putbuf(buf, *arg2);
  			f->eax = *arg2;
        break;
  		}
      else
      {
        file_ptr = t->fd_array[*arg0];
        if (file_ptr == NULL)
        {
          f->eax = 0;
          break;
        }
        if(file_ptr->inode->data.is_directory)
        {
          if(debug_fs) printf("\tCan't write to directory\n");
          f->eax=-1;
          break;
        }
        // if (file_ptr->inode->data.is_directory == true)
        // {
        //   if (debug_fs) printf("trying to write to a directory\n");
        //   f->eax = -1;
        //   break;
        // }
        // sema_down(t->filesys_sema_ptr);
        // f->eax = file_write(file_ptr, buf, *arg2);
        // sema_up(t->filesys_sema_ptr);
        //printf("\tfile_ptr->inode->sector = %d\n", file_ptr->inode->sector);
        f->eax = file_write(file_ptr, buf, *arg2);
      }
  		break;

    case SYS_SEEK:
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];
      file_seek(file_ptr, *arg1);
      if (debug_fs) printf("file_seek to %d\n", *arg1);
      break;

    case SYS_TELL:
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];
      if (debug_fs) printf("file_tell to %d\n", file_tell(file_ptr));
      f->eax = file_tell(file_ptr);
      break;

    case SYS_CLOSE:
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];
      // sema_down(t->filesys_sema_ptr);
      // file_close(file_ptr);
      // sema_up(t->filesys_sema_ptr);
      if (file_ptr == NULL)
      {
        f->eax = -1;
        break;
      }

      file_close(file_ptr);

      t->fd_array[*arg0] = NULL;
      t->files_closed++;
      break;

    case SYS_CHDIR:
      if (strcmp(*arg0, "/") == 0)
      {
        t->current_directory = 1;
        success = true;
      }
      else if (strcmp(*arg0, ".") == 0)
      {
        success = true;
      }
      else if (strcmp(*arg0, "..") == 0)
      {
        inode = inode_open(t->current_directory);
        t->current_directory = inode->data.parent_dir;
        inode_close(inode);
        success = true;
      }
      else
      {
        temp_inode = inode_open(t->current_directory);
        if (debug_fs) printf("\tcurrent dir inumber = %d\n", t->current_directory);
        dir = dir_open(temp_inode);
        if (debug_fs) printf("\tdir->inode->sector = %d\n", dir->inode->sector);
        inode = get_last_inode(*arg0, last_file);
        dir_close(dir);
        if (inode != NULL)
        {
          if (inode->removed)
          {
            success = false;
            break;
          }
          else
          {
            t->current_directory = inode->sector;
            inode_close(inode);
            success = true;
          }          
        }
        else
        {
          success = false;
        }
      }     
      
      f->eax = success;
      break;

    case SYS_MKDIR:
      if (debug_fs) printf("\tSYS_MKDIR:\n");
      //success = chop_dirline(*arg0, inode, last_file);
      //temp_inode = inode_open(t->current_directory);
      // if (debug_fs) printf("\tcurrent dir inumber = %d\n", t->current_directory);
      //dir = dir_open(temp_inode);
      inode = get_last_inode(*arg0, last_file);
      temp_inode = inode_open(temp_dir_inumber);
      dir = dir_open(temp_inode);
      //if (debug_fs) printf("\tlast_file = %s\n", last_file);
      if (inode == NULL)
      {
        free_map_allocate(1, &new_file_sector);
        if(dir_create(new_file_sector, 16))
        {
          success = dir_add(dir, last_file, new_file_sector);
          inode = inode_open(new_file_sector);
          inode->data.parent_dir = dir->inode->sector;
          inode_close(inode);
          dir_close(dir);

          if(success == false)
          {
            free_map_release(new_file_sector, 1);
          }
        }

        //inode_close(inode);
      }
      else
        success = false;

      f->eax = success;
      break;

    case SYS_READDIR:                /* Reads a directory entry. */
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];

      if (file_ptr == NULL)
      {
        f->eax = 0;
        break;
      }

      if (file_ptr->is_dir == false)
      {
        f->eax = 0;
        break;
      }

      f->eax = dir_readdir(file_ptr->dir_ptr, *arg1);
      break;

    case SYS_ISDIR:                  /* Tests if a fd represents a directory. */
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];

      if (file_ptr == NULL)
      {
        f->eax = -1;
        break;
      }

      f->eax = file_ptr->is_dir;
      break;

    case SYS_INUMBER:                 /* Returns the inode number for a fd. */
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];

      if (file_ptr == NULL)
      {
        f->eax = -1;
        break;
      }

      f->eax = file_ptr->inode->sector;
      break;

  	default:
  		printf("This system call has not yet been implemented: %d\n", *syscall_num_ptr);
  		thread_exit();
      break;
  }
}
