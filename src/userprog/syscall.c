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

static struct inode *get_last_inode(char *dirline, struct dir *current_dir, char *last_file)
{
  if (debug_fs) printf("\tget_last_inode(): dirline = %s, cur_dir_inode = %d @ %p\n", dirline, current_dir->inode->sector, current_dir);
  int cd_sector = current_dir->inode->sector;
  int dirline_length = strlen(dirline) + 1;
  if (debug_fs) printf("\tcur_dir_inode = %d @ %p\n", current_dir->inode->sector, current_dir);
  char *dirline_cpy = calloc(dirline_length, sizeof(char));
  if (debug_fs) printf("\tcur_dir_inode = %d @ %p\n", current_dir->inode->sector, current_dir);
  strlcpy(dirline_cpy, dirline, dirline_length);
  if (debug_fs) printf("\tcur_dir_inode = %d @ %p\n", current_dir->inode->sector, current_dir);

  char *save_ptr, *token;
  struct inode *inode;
  struct dir *next_dir = NULL;
  for (token = strtok_r(dirline_cpy, "/", &save_ptr);
        token != NULL;
        token = strtok_r(NULL, "/", &save_ptr))
  {
    strlcpy(last_file, token, strlen(token)+1);
    if (debug_fs) printf("\t\t token = %s\n", token);
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
      current_dir = dir_parent(current_dir);
    }

    if(strlen(token)>14)
    {
      if(debug_fs) printf("\t\tDirectory name is too long\n");
      inode = NULL;
      break;
    }

    if (debug_fs) printf("\t\ttrying to lookup '%s' in the dir = %d @ %p\n", token, current_dir->inode->sector, current_dir);
    struct inode *temp_inode = inode_open(cd_sector);
    current_dir = dir_open(temp_inode);
    if (debug_fs) printf("\t\tFOR REAL trying to lookup '%s' in the dir = %d @ %p\n", token, current_dir->inode->sector, current_dir);

    if(dir_lookup(current_dir, token, &inode))
    {
      if(debug_fs) printf("\t\tFound %s in current directory\n", token);
      if(inode->data.is_directory)
      {
        next_dir = dir_open(inode);
        dir_close(current_dir);
        current_dir = next_dir;
        if (debug_fs) printf("\t\tchanged current dir inumber to %d and dir @ %p\n", current_dir->inode->sector, current_dir);
      }
    }
    else
    {
      inode = NULL;
      break;
    }
  }

  if (debug_fs) printf("\t\tcurrent dir inumber = %d and dir @ %p\n", current_dir->inode->sector, current_dir);
  temp_dir_inumber = current_dir->inode->sector;
  if (debug_fs) printf("\t\ttemp_dir_inumber = %d\n", temp_dir_inumber);

  free(dirline_cpy);
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
  struct thread *t = thread_current ();
  struct file *file_ptr;
  struct dir *dir;
  struct inode *inode;
  struct inode *temp_inode;

  bool success = false;
  char last_file[15];
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
      //success = chop_dirline(*arg0, inode, last_file);
      temp_inode = inode_open(t->current_directory);
      // if (debug_fs) printf("\tcurrent dir inumber = %d\n", t->current_directory);
      dir = dir_open(temp_inode);
      // if (debug_fs) printf("\t!!!dir address before get_last_inode = %p\n", dir);
      // if (debug_fs) printf("\t!!!dir inumber before get_last_inode = %d\n", dir->inode->sector);
      inode = get_last_inode(*arg0, dir, last_file);
      // if (debug_fs) printf("\t!!!dir address after get_last_inode = %p\n", dir);
      // if (debug_fs) printf("\t!!!dir inumber after get_last_inode = %d\n", dir->inode->sector);
      if (inode != NULL)
      {
        f->eax = false;
        break;
      }

      dir_close(dir);

      
      free_map_allocate(1, &new_file_sector);
      inode_create(new_file_sector, 0, 0);
      temp_inode = inode_open(temp_dir_inumber);
      dir = dir_open(temp_inode);
      /* Add the file as an entry to it's parent directory */
      success = dir_add(dir, last_file, new_file_sector);
      dir_close(dir);

      f->eax = success;
  		break;

    case SYS_REMOVE:
      if (valid_array[0] != 1)
      {
        thread_exit();
      }
      f->eax = filesys_remove((char*)*arg0);
      break;

  	case SYS_OPEN:
      if (valid_array[0] != 1)
      {
        thread_exit();
      }

      if(t->fd_array[127] != NULL)
      {
        f->eax = -1;
        break;
      }
      
      const char *open_buf = *arg0;

      sema_down(t->filesys_sema_ptr);
      file_ptr = filesys_open(open_buf);
      sema_up(t->filesys_sema_ptr);


      // temp_inode = inode_open(t->current_directory);


      // if (inode->data.is_directory)
      //   file_ptr = dir_open(inode);
      // else
      //   file_ptr = file_open(inode);


  		if (file_ptr == NULL)
  		{
  			f->eax = -1;
  			break;
  		}
  		
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
      sema_down(t->filesys_sema_ptr);
      f->eax = file_length(file_ptr);
      sema_up(t->filesys_sema_ptr);
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
        sema_down(t->filesys_sema_ptr);
        f->eax = file_read(file_ptr, (void*)*arg1, (off_t)*arg2);
        sema_up(t->filesys_sema_ptr);
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

        sema_down(t->filesys_sema_ptr);
        f->eax = file_write(file_ptr, buf, *arg2);
        sema_up(t->filesys_sema_ptr);
      }
  		break;

    case SYS_SEEK:
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];
      file_seek(file_ptr, *arg1);
      break;

    case SYS_TELL:
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];
      file_tell(file_ptr);
      break;

    case SYS_CLOSE:
      if (*arg0 < 2 || *arg0 > 127)
      {
        break;
      }
      file_ptr = t->fd_array[*arg0];
      sema_down(t->filesys_sema_ptr);
      file_close(file_ptr);
      sema_up(t->filesys_sema_ptr);
      t->fd_array[*arg0] = NULL;
      t->files_closed++;
      break;

    case SYS_CHDIR:      
      temp_inode = inode_open(t->current_directory);
      if (debug_fs) printf("\tcurrent dir inumber = %d\n", t->current_directory);
      dir = dir_open(temp_inode);
      if (debug_fs) printf("\tdir->inode->sector = %d\n", dir->inode->sector);
      inode = get_last_inode(*arg0, dir, last_file);
      dir_close(dir);
      if (inode != NULL)
      {
        t->current_directory = inode->sector;
        //inode_close(inode);
        success = true;
      }

      f->eax = success;
      break;

    case SYS_MKDIR:
      if (debug_fs) printf("\tSYS_MKDIR:\n");
      //success = chop_dirline(*arg0, inode, last_file);
      temp_inode = inode_open(t->current_directory);
      // if (debug_fs) printf("\tcurrent dir inumber = %d\n", t->current_directory);
      dir = dir_open(temp_inode);
      inode = get_last_inode(*arg0, dir, last_file);
      //if (debug_fs) printf("\tlast_file = %s\n", last_file);
      if (inode == NULL)
      {
        free_map_allocate(1, &new_file_sector);
        if(dir_create(new_file_sector, 16))
        {
          success = dir_add(dir, last_file, new_file_sector);
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

  	default:
  		printf("This system call has not yet been implemented: %d\n", *syscall_num_ptr);
  		thread_exit();
      break;
  }
}
