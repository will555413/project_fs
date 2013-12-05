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

int debug_fs = 1;

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

static struct inode *get_last_inode(char *dirline, struct dir *current_dir, char *file_name)
{
  int dirline_length = strlen(dirline) + 1;
  char *dirline_cpy = calloc(dirline_length, sizeof(char));
  strlcpy(dirline_cpy, dirline, dirline_length);

  char *save_ptr, *token;
  struct inode *inode;
  struct dir *next_dir;
  for (token = strtok_r(dirline_cpy, "/", &save_ptr);
        token != NULL;
        token = strtok_r(NULL, "/", &save_ptr))
  {
    if(strcmp(token, "."))
      continue;

    if(strcmp(token, ".."))
    {
      current_dir = dir_parent(current_dir);
    }

    if(strlen(token)>14)
    {
      if(debug_fs) printf("Directory name is too long\n");
      return NULL;
    }

    if(dir_lookup(current_dir, token, &inode))
    {
      if(inode->data.is_directory)
      {
        next_dir = dir_open(inode);
        dir_close(current_dir);
        current_dir = next_dir;
      }
    }
    else
      return NULL;
  }
  strlcpy(file_name, token, strlen(token));
  free(dirline_cpy);
  return inode;
}

/* Find the last file provide in dirline and copy it to
  last_file, then return the length of last_file */
static int get_last_file(char *dirline, char *last_file)
{
  int dirline_length = strlen(dirline) + 1;
  char *dirline_cpy = calloc(dirline_length, sizeof(char));
  strlcpy(dirline_cpy, dirline, dirline_length);
  char *save_ptr, *token, *prev_token;
  if (debug_fs) printf("get_last_file(): dirline_cpy = %s at %p\n", dirline_cpy, dirline_cpy);
  for (token = strtok_r(dirline_cpy, "/", &save_ptr);
      token != NULL;
      token = strtok_r(NULL, "/", &save_ptr))
  {
    prev_token = token;
  }

  strlcpy(last_file, prev_token, strlen(prev_token));
  free(dirline_cpy);
  return strlen(last_file);
}

/* Removes last file from dirline and returns inode of the
    new last file */
static void chop_dirline(char *dirline, struct inode *inode, char *last_file)
{
  struct thread *t = thread_current ();
  struct inode *cur_dir_inode;
  int str_idx;
  char file_name[15];

  /* Open inode of this thread's working directory */
  cur_dir_inode = inode_open(t->current_directory);

  /* Find index of the '/' before the last file and set to null */
  str_idx = strlen(dirline) - get_last_file(dirline, last_file) - 1;
  dirline[str_idx] = '\0';

  /* Search current directory (or root) for the new last file,
      and set the provided inode to it's inode */
  inode = get_last_inode(dirline, cur_dir_inode, file_name);
  inode_close(cur_dir_inode);
}

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
  char file_name[15];
  char last_file[15];
  // char filepath_copy[256];
  int str_idx;
  int new_file_sector = -1;
  // char *file_list[32];

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
      // strlcpy(filepath_copy, *arg0, strlen(*arg0));
      // get_file_list(filepath_copy, file_list);
      chop_dirline(*arg0, inode, last_file);
      free_map_allocate(1, &new_file_sector);
      inode_create(new_file_sector, 0, 0);
      temp_inode = inode_open(new_file_sector);
      temp_inode->data.parent_dir = inode->sector;
      block_write(fs_device, temp_inode->sector, &temp_inode->data);
      inode_close(temp_inode);

      /* Add the file as an entry to it's parent directory */
      dir = dir_open(inode);
      success = dir_add(dir, new_file_sector, file_name);
      dir_close(inode);

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

      //sema_down(t->filesys_sema_ptr);
      //file_ptr = filesys_open(open_buf);
      //sema_up(t->filesys_sema_ptr);
      temp_inode = inode_open(t->current_directory);


      str_idx = strlen(*arg0) - get_last_file(*arg0, last_file) - 1;
      arg0[str_idx] = '\0';

      inode = get_last_inode(*arg0, temp_inode, file_name);
      inode_close(temp_inode);


      if (inode->data.is_directory)
        file_ptr = dir_open(inode);
      else
        file_ptr = file_open(inode);

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
      inode = get_last_inode(*arg0, temp_inode, file_name);
      inode_close(temp_inode);
      if (inode != NULL)
      {
        t->current_directory = inode->sector;
        inode_close(inode);
        success = true;
      }

      f->eax = success;
      break;

    case SYS_MKDIR:
      chop_dirline(*arg0, inode, last_file);
      if (inode != NULL)
      {
        free_map_allocate(1, &new_file_sector);
        if(dir_create(new_file_sector, 0))
        {
          dir = dir_open(inode);
          success = dir_add(dir, new_file_sector, last_file);
          dir_close(dir);

          if(success == false)
          {
            free_map_release(new_file_sector, 1);
          }
        }

        inode_close(inode);
      }

      f->eax = success;
      break;

  	default:
  		printf("This system call has not yet been implemented: %d\n", *syscall_num_ptr);
  		thread_exit();
      break;
  }
}
