#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#include "userprog/syscall.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	char *save_ptr;
	strtok_r(file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	//printf("!! thread name !! %s", file_name); // TODO RM
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct thread *cur = thread_current();
	memcpy(&cur->parent_if, if_, sizeof(struct intr_frame));

	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, cur);
	if(tid == TID_ERROR) return TID_ERROR;

	struct thread *child = get_child_process(tid);

	// 현재 스레드는 생성만 완료된 상태이다. 생성되어서 ready_list에 들어가고 실행될 때 __do_fork 함수가 실행된다.
    // __do_fork 함수가 실행되어 로드가 완료될 때까지 부모는 대기한다.
	// sema는 0으로 초기화 된다. // 즉 부모다 sema_down을 먼저 해도 대기하게 된다.
	// 자식이 먼저 sema_up을 하면 진행
	sema_down(&child->load_sema);

	if (child->exit_status == TID_ERROR) {
		return TID_ERROR;
	}
	return tid;
}

struct thread *get_child_process(int tid) {
	
	struct thread *cur = thread_current();
	struct list *child_list = &cur->child_list;

	for (struct list_elem *e = list_begin(child_list); e!= list_end(child_list); e = list_next(e)) {
		struct thread *t = list_entry(e, struct thread, child_elem);

		if (t->tid == tid) return t;
	}
	return NULL;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. 
 page table을 복제하는데 사용되는 함수 */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if(is_kernel_vaddr(va)) return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (parent_page == NULL) return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (newpage == NULL) return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->parent_if;
	bool succ = true;
	

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
	if_.R.rax = 0; // child process의 리턴값은 0
	

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	// 복사 file descript table
	for (int i =0; i<FDT_COUNT_LIMIT; i++){
		struct file *file = parent->fdt[i];
		if (file == NULL) {
			continue;
		}
		if (file > 2) {
			file = file_duplicate(file);
		}
		current->fdt[i] = file;
	}
	current->next_fd = parent->next_fd;
	sema_up(&current->load_sema);

	process_init();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	sema_up(&current->load_sema);
	exit(TID_ERROR);
}



/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
// f_name을 parsing하고 user_stack에 매개변수를 push하는 역할.
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();  // thread르ㄹ 사용하는데 왜 프로세스를 죽이지? 
	
	char *parse[64];
	char *token, *save_ptr;
	int count = 0;

	//아래 코드가 무엇을 의미하는거지?
	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) 
		parse[count++] = token;

	/* And then load the binary */
	lock_acquire(&filesys_lock);
	success = load(file_name, &_if);
	lock_release(&filesys_lock);

	if (!success)
	{
		palloc_free_page(file_name);
		return -1;
	}

	
	// argument passing
	argument_stack(parse, count, &_if.rsp); 
	_if.R.rdi = count;
	_if.R.rsi = (char *)_if.rsp + 8;

	
	//hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true);  //user stack을 16진수로 출력

	/* If load failed, quit. */
	palloc_free_page (file_name);

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


void argument_stack(char **parse, int count, void **rsp) // 주소를 전달받았으므로 이중 포인터 사용
{
	// 프로그램 이름, 인자 문자열 push
	for (int i = count - 1; i > -1; i--)
	{
		for (int j = strlen(parse[i]); j > -1; j--)
		{
			(*rsp)--;					  // 스택 주소 감소
			**(char **)rsp = parse[i][j]; // 주소에 문자 저장
		}
		parse[i] = *(char **)rsp; // parse[i]에 현재 rsp의 값 저장해둠(지금 저장한 인자가 시작하는 주소값)
	}

	// 정렬 패딩 push
	int padding = (int)*rsp % 8;
	for (int i = 0; i < padding; i++)
	{
		(*rsp)--;
		**(uint8_t **)rsp = 0; // rsp 직전까지 값 채움
	}

	// 인자 문자열 종료를 나타내는 0 push
	(*rsp) -= 8;
	**(char ***)rsp = 0;

	// 각 인자 문자열의 주소 push
	for (int i = count - 1; i > -1; i--)
	{
		(*rsp) -= 8; // 다음 주소로 이동
		**(char ***)rsp = parse[i];
	}

	// return address push
	(*rsp) -= 8;
	**(void ***)rsp = 0;
}

// 인자로 들어온 file에 대한 fd값을 할당. 
int process_add_file(struct file *f) {
	struct thread *curr = thread_current();
	struct file **fdt = curr->fdt;


	// 여기서 미리 제한을 걸어둔 범위 안에서 빈 자리 탐색 -> 근데 만약에 자리가 없으면 어떻게 대기할 것인지? 
	// 대기하지 않는다. 그냥 -1을 리턴하고 끝낸다.
	while (curr->next_fd < FDT_COUNT_LIMIT && fdt[curr->next_fd]) {
		curr -> next_fd++;
	}
	if (curr->next_fd >= FDT_COUNT_LIMIT) return -1;

	fdt[curr->next_fd] = f;
	return curr->next_fd;
}

struct file *process_get_file(int fd) {
	struct thread *curr = thread_current();
	struct file **fdt = curr -> fdt;

	if (fd < 2 || fd >= FDT_COUNT_LIMIT) return NULL;
	return fdt[fd];
}

// fdt에서 file 객체를 제거하는 함수
void process_close_file(int fd) {
	struct thread *curr = thread_current();
	struct file **fdt = curr->fdt;
	if (fd < 2 || fd >= FDT_COUNT_LIMIT) {
		return NULL;
	}
	fdt[fd] = NULL;
}




/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	struct thread *child = get_child_process(child_tid);
    if (child == NULL) {// 1) 자식이 아니면 -1을 반환한다.
        return -1;
	}

    // 2) 자식이 종료될 때까지 대기한다. (process_exit에서 자식이 종료될 때 sema_up 해줄 것이다.)
    sema_down(&child->wait_sema);
    // 3) 자식이 종료됨을 알리는 `wait_sema` signal을 받으면 현재 스레드(부모)의 자식 리스트에서 제거한다.
    list_remove(&child->child_elem);
    // 4) 자식이 완전히 종료되고 스케줄링이 이어질 수 있도록 자식에게 signal을 보낸다.
    sema_up(&child->exit_sema);

    return child->exit_status; // 5) 자식의 exit_status를 반환한다.
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	
	for (int i = 2; i < FDT_COUNT_LIMIT; i++)
	{
		if (curr->fdt[i] != NULL) {
			close(i);
		}
	}
	palloc_free_multiple(curr->fdt, FDT_PAGES);
	//palloc_free_page(curr->fdt);
	file_close(curr->running);
	process_cleanup();

	sema_up(&curr->wait_sema);
	sema_down(&curr->exit_sema);
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];     // ELF 식별자. 첫 4바이트는 0x7F 'E' 'L' 'F'로 시작
	uint16_t e_type;					  // 실행 파일인지, 객체 파일인지 
	uint16_t e_machine;					  // 아키텍처 
	uint32_t e_version;					  // ELF 버전 항시 1
	uint64_t e_entry;					  // 프로그램 시작 즈소(entry point), 즉 rip 초기 값
	uint64_t e_phoff;					  // Program Header Table 시작 위치(파일 오프셋)
	uint64_t e_shoff;					  // Section Header Table 시작 위치 (사용 안함)
	uint32_t e_flags;					  // CPU-specific 플래그 (사용 안함)	
	uint16_t e_ehsize;					  // ELF 헤더 크기
	uint16_t e_phentsize;				  // Program 헤더 크기
	uint16_t e_phnum;					  // Program 헤더 개수
	uint16_t e_shentsize;				  // Section Header 크기
	uint16_t e_shnum;					  // Section Header 개수
	uint16_t e_shstrndx;				  // Section 이름 문자열 테이블 인덱스
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	// ELF 헤더 읽기 및 유효성 검사
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	//Program Header 읽기 & LOAD 세그먼트 처리
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	t->running = file;
	// 현재 실행중인 파일은 수정할 수 없게 만든다.
	file_deny_write(file);

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry; //entry point 초기화
	// rip: program counter

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// 파일을 여기서 닫지 않고 스레드가 삭제될 때 process_exit에서 닫는다.
	// Why? 파일을 닫으면 쓰기 작업이 다시 허용되기 때문이다. 
	// 따라서 프로세스의 실행 파일에 대한 쓰기를 거부하려면 해당 파일을 프로세스가 실행 중인 동안 계속 열어두어야 한다.

	// file_close(file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

bool lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *) aux;

	// 파일의 position을 ofs로 지정
	file_seek(lazy_load_arg->file, lazy_load_arg->ofs);
	
	// 파일을 read_bytes 만큼 물리 프레임에 읽어 들임
	if (file_read(lazy_load_arg->file, page->frame->kva, lazy_load_arg->read_bytes) != (int)(lazy_load_arg->read_bytes)) {
		palloc_free_page(page->frame->kva);
		return false;
	}

	// 다 읽은 지점부터 zero_bytes만큼 0으로 채운다
	memset(page->frame->kva + lazy_load_arg->read_bytes, 0, lazy_load_arg->zero_bytes);
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
/* 
	file : 내용이 담긴 파일 객체
	ofs : 이 페이지에서 읽기 시작할 위치
	read_bytes : 이 페이지에서 읽어야 하는 바이트 수
	zero_bytes : 이 페이지에서 read_bytes 만큼 읽고 공간이 남아 0으로 채워야 하는 바이트 수
	lazy
*/
static bool load_segment 
	(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0); 		// read_bytes + zero_bytes가 페이지 크기(PGSIZE)의 배수인지 확인
	ASSERT (pg_ofs (upage) == 0);							// upage가 페이지 정렬되어 있는지 확인
	ASSERT (ofs % PGSIZE == 0);								// ofs가 페이지 정렬되어 있는지 확인

	while (read_bytes > 0 || zero_bytes > 0) {  		// read_bytes와 zero_bytes가 0보다 큰 동안 루프를 실행
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		
		// vm_alloc_page_with_initializer에 제공할 aux 인수로 필요한 보조 값들을 설정해야 합니다.
		// loading을 위해 필요한 정보를 포함하는 구조체를 만들어야 합니다.
		struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)malloc(sizeof(struct lazy_load_arg));
		lazy_load_arg->file = file;					 // 내용이 담긴 파일 객체
		lazy_load_arg->ofs = ofs;					 // 이 페이지에서 읽기 시작할 위치

		lazy_load_arg->read_bytes = page_read_bytes; // 이 페이지에서 읽어야 하는 바이트 수
		lazy_load_arg->zero_bytes = page_zero_bytes; // 이 페이지에서 read_bytes만큼 읽고 공간이 남아 0으로 채워야 하는 바이트 수
		
		
		// vm_alloc_page_with_initializer를 호출하여 대기 중인 객체를 생성합니다.
		if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, lazy_load_arg))
			return false;

		/* Advance. */
		// 다음 반복을 위하여 읽어들인 만큼 값을 갱신합니다.
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += page_read_bytes;

	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
// USER_STACK에서 스택의 PAGE를 생성합니다. 성공하면 true를 반환합니다.
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;

	// 스택은 아래로 성장하므로, USER_STACK에서 PGSIZE만큼 아래로 내린 지점에서 페이지를 생성한다.
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: stack_bottom에 스택을 매핑하고 페이지를 즉시 요청하세요.
	 * TODO: 성공하면, rsp를 그에 맞게 설정하세요.
	 * TODO: 페이지가 스택임을 표시해야 합니다. */
	/* TODO: Your code goes here */

	// 1) stack_bottom에 페이지를 하나 할당받는다.
	if (vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, 1))
	// VM_MARKER_0: 스택이 저장된 메모리 페이지임을 식별하기 위해 추가
	// writable: argument_stack()에서 값을 넣어야 하니 True
	{
		// 2) 할당 받은 페이지에 바로 물리 프레임을 매핑한다.
		//printf("setup stack entry point \n");
		success = vm_claim_page(stack_bottom);
		if (success)
			// 3) rsp를 변경한다. (argument_stack에서 이 위치부터 인자를 push한다.)
			if_->rsp = USER_STACK;
	}
	return success;
}
#endif /* VM */
