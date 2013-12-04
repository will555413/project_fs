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
#include "devices/shutdown.h"
#include "devices/timer.h"

static void syscall_handler (struct intr_frame *);
static int is_valid_pointer(int *uaddr);

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
      sema_down(t->filesys_sema_ptr);
  		f->eax = filesys_create((char*)*arg0, *arg1);
      sema_up(t->filesys_sema_ptr);
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
      dirline = *arg0;
      //f->eax = chdir(dir);
      for (token = strtok_r(dirline,"/",save_ptr);
           token != NULL;
           token = strtok_r(NULL,"/",save_ptr))
      {
        if(strcmp(token, "."))
          continue;
        if(strcmp(token, ".."))
        {
          dir = dir->prev;/*need to work on how to get previous dir*/
        }
        if(strlen(token)>14)
        {
          if(debug_fs) printf("Directory name is too long\n");
          f->eax = 0;
          break;
        }
        struct inode **inode;
        if(dir_lookup (dir/*getting current dir?*/, token, inode))
        {
          dir = dir_open(inode);
        }
        else
        {
          if(debug_fs) printf("Directory not found\n");
          f->eax = 0;
          break;
        }
      }
      f->eax = 1;
        
      break;

    case SYS_MKDIR:
      dirline = *arg0;
      for (token = strtok_r(dirline,"/",save_ptr);
           token != NULL;
           token = strtok_r(NULL,"/",save_ptr))
      {
        if(strcmp(token, "."))
          continue;
        if(strcmp(token, ".."))
        {
          dir = dir->prev;/*need to work on how to get previous dir*/
        }
        if(strlen(token)>14)
        {
          if(debug_fs) printf("Directory name is too long\n");
          f->eax = 0;
          break;
        }
        struct inode **inode;
        if(dir_lookup (dir/*getting current dir?*/, token, inode))
        {
          dir = dir_open(inode);
        }
        else if(strtok_r(NULL,"/",save_ptr)==NULL)
        {
          //create a new directory and add it to current directory
          //Struct dir *dir
        }
        else
        {
          if(debug_fs) printf("Directory not found\n");
          f->eax = 0;
          break;
        }
      }
      f->eax = 1;
      break;

  	default:
  		printf("This system call has not yet been implemented: %d\n", *syscall_num_ptr);
  		thread_exit();
      break;
  }
}
