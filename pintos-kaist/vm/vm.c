/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
// init.c에서 vm_init() 호출
void
vm_init (void) {
	vm_anon_init (); //익명 페이지(anonymous page) 관리 초기화 (스왑 사용 등)
	vm_file_init (); // 파일-mapped 페이지 관리 초기화
#ifdef EFILESYS  /* For project 4 */
	pagecache_init (); //프로젝트 4: 파일 시스템 캐시 초기화 (optional)
#endif
	register_inspect_intr (); //디버깅용 페이지 테이블 검사 인터럽트 등록
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* 
사용자 공간 주소 upage에 가상 페이지를 할당한다.
VM_UNINIT 타입이 아닌 일반 타입 (VM_ANON, VM_FILE)을 받아서 내부적으로 UNINIT 페이지로 래핑
아래 함수는 다음을 수행한다.
1. 해당 upage에 이미 페이지가 있는지 spt_find_page()로 확인
2. 없다면 -> uninit_new()로 초기화 되지 않은 페이지 생성, 이후 spt에 등록 (spt_insert_page())
- 주로 lazy-loading(지연 로딩) 페이지 생성에 사용된다.
*/
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		struct page *p = (struct page *) malloc (sizeof(struct page));
		
		// type에 따라 초기화 함수를 가져옴
		bool (*page_initializer)(struct page *, enum vm_type, void *);

		switch (VM_TYPE(type)) {
			case VM_ANON:
				page_initializer = anon_initializer;
				break;
			case VM_FILE:
				page_initializer = file_backed_initializer;
				break;
		}

		// page를 uninit type으로 초기화. init == lazy_load_segment
		uninit_new(p, upage, init, type, aux, page_initializer);

		p->writable = writable;
		return spt_insert_page(spt, p);
		
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
//보조 페이지 테이블(SPT)에서 해당 VA(가상 주소)에 해당하는 페이지를 찾아 반환.
	// 내부적으로 해시 테이블을 사용해서 va 주소 기반으로 검색합니다.
struct page * spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	
	page = malloc(sizeof(struct page));
	struct hash_elem *e;

	page -> va = va;
	e = hash_find(&spt, &page->hash_elem);

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. 
새 페이지를 보조 페이지 테이블(SPT)에 삽입합니다.
이미 존재하면 false 반환.
보통 hash_insert() 등의 해시 함수로 구현. */
bool spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	
	return hash_insert(&spt, &page->hash_elem) == NULL ? true : false;
}

// vm_dealloc_page()를 호출해서 페이지와 프레임을 해제합니다.
void spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
// 메모리 부족 시 페이지를 교체하는 로직입니다.
// 교체할 프레임을 선택하는 정책 구현 (예: FIFO, LRU)
static struct frame * vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
//메모리 부족 시 페이지를 교체하는 로직입니다.
// 해당 페이지를 디스크로 내보내고 스왑 슬롯 등에 저장합니다.
static struct frame * vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
// 새로운 프레임을 할당하거나, 부족하면 vm_evict_frame()으로 프레임 확보.
// 사용자 풀에서 새로운 물리 페이지(frame)를 할당
static struct frame * vm_get_frame (void) {
	struct frame *frame = NULL;
	
	void *kva = palloc_get_page(PAL_USER);

	if (kva == NULL) PANIC("todo");

	frame = malloc(sizeof(struct frame));  // frame 할당
	frame->kva = kva;					   // 프레임 멤버 초기화


	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
// 현재 스택 영역에 없는 주소가 접근되면 스택을 자동 확장해주는 로직
static void vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
// COW 중인데 write시도해서 page fault 발생함. 해당 페이지 복사해서 독립적인 페이지로 할당하는 함수
static bool vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
// exception.c에서 page_fault()가 호출될 때, vm_try_handle_fault()를 호출함.
// 이 함수는 페이지 폴트가 발생했을 때 호출되어, 이를 처리하려 시도하는 함수
/* 
1. not_present == true: 페이지가 아직 메모리에 로딩되지 않음 → vm_claim_page()로 메모리에 올림
2. write == true && page가 write_protected: → vm_handle_wp() 호출 
3. 유효하지 않은 접근 (예: NULL, 커널 주소, 잘못된 위치): → 실패 반환
*/ //여기가 호출됨.
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

    if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
    {
        /* TODO: Validate the fault */
        page = spt_find_page(spt, addr);
        if (page == NULL)
            return false;
        if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
            return false;
        return vm_do_claim_page(page);
    }
    return false;
}

/*
💡 질문.왜 vm_try_handle_fault()가 중요한가?
운영체제는 실제로 모든 페이지를 한 번에 메모리에 올리지 않음.
→ Lazy Loading (지연 로딩) 방식으로 필요할 때만 로드함.
→ 그러다 접근하면 fault가 발생하고, 이 함수를 통해 페이지를 로딩하거나 복사해서 메모리에 넣어줌.
*/

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
// 특정 가상 주소에 해당하는 페이지를 활성화(즉, 프레임에 올림).
bool vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL) return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. 
실제 물리 프레임 할당 (vm_get_frame() 호출)

MMU에 해당 VA와 프레임 물리 주소를 매핑

swap_in() 호출하여 실제 페이지 데이터 복원 */
static bool vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *curr = thread_current();
	pml4_set_page(curr->pml4, page->va, frame->kva, page->writable);

	return swap_in (page, frame->kva);
}

// SPT에 저장된 page 구조체에 대한 해시값을 계산해주는 함수
// 해시 테이블의 내부 버킷 배열에서 어떤 버킷(리스트)에 해당 page를 저장할지 결정
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

// 해시 테이블 내부의 충돌 해결을 위해 사용하는 정렬 기준 함수
// Pintos의 해시 테이블은 같은 해시값에 여러 개가 들어올 수 있어, 정렬을 유지
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);

	return a->va < b->va;
}
/*
🧱 supplemental_page_table_* 계열

SPT는 유저 주소 공간의 가상 페이지 → 실제 페이지 구조체 매핑을 담당

init: 해시 테이블 등 자료구조 초기화

copy: 프로세스 fork 시 부모의 SPT를 복사

kill: 종료 시 모든 페이지 자원 해제, 변경된 내용 디스크에 저장
*/ 
/* Initialize new supplemental page table */
// process.c 내부 새로운 스레드가 시작될 때 __do_fork()에서 호출
void supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(spt, page_hash, page_less, NULL); // hash table 초기화
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
