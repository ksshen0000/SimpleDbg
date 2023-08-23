#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <assert.h>
#include <capstone/capstone.h>
#include <map>
#include <elf.h>
#include <string>
#include <cstring>
#include <vector>
#include <set>
#define BUFFSIZE 1024
static std::map<long long, cs_insn> instructions;
std::set<unsigned long long > breakpoints;
class range{
    public:
    unsigned long long start;
    unsigned long long end;
};
class minfo{
    public:
    uint8_t *start;
    size_t size;
};

class snapshot{
    public:
    int used;
    struct user_regs_struct ss_regs;
    std::vector<minfo> minfos;
    std::vector<range> child_infos;
};
snapshot anchor_snapshot;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}
void disassemble_code_sections( Elf64_Shdr *section_header_table, int num_sections, unsigned char *buffer) {
    // Initialize Capstone
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Failed to initialize Capstone\n");
        return;
    }

    // Iterate over all code sections
    printf("Disassembly of code sections:\n");
    for (int i = 0; i < num_sections; i++) {
        Elf64_Shdr *section_header = &section_header_table[i];
        if (section_header->sh_type == SHT_PROGBITS &&
            (section_header->sh_flags & (SHF_EXECINSTR ))) {
            Elf64_Addr section_address = section_header->sh_addr;
            Elf64_Xword section_size = section_header->sh_size;
            printf("section size: %lx\n",section_size);

            // Disassemble the code section
            cs_insn *insn;
            size_t count = cs_disasm(handle, buffer + section_header->sh_offset, section_size, section_address, 0, &insn);
            if (count > 0) {
                for (size_t j = 0; j < count; j++) {
                    // printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                    instructions[insn[j].address] = insn[j];
                }

                // Clean up Capstone resources
                cs_free(insn, count);
            } else {
                printf("Failed to disassemble section at address 0x%lx\n", section_address);
            }
        }
    }

    // Clean up Capstone
    cs_close(&handle);
}

int readelf_disassemble(const char * filename){
    // Open the ELF file
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", filename);
        return 1;
    }

    // Read the ELF header
    Elf64_Ehdr elf_header;
    fread(&elf_header, sizeof(Elf64_Ehdr), 1, file);

    // Read the section header table
    int num_sections = elf_header.e_shnum;
    int section_header_size = elf_header.e_shentsize;
    Elf64_Off section_header_offset = elf_header.e_shoff;
    fseek(file, section_header_offset, SEEK_SET);

    Elf64_Shdr *section_header_table = (Elf64_Shdr *)malloc(section_header_size * num_sections);
    fread(section_header_table, section_header_size, num_sections, file);

    // Find the size of the file
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory to hold the entire file
    unsigned char *buffer = (unsigned char *)malloc(file_size);
    if (!buffer) {
        printf("Memory allocation failed\n");
        fclose(file);
        free(section_header_table);
        return 1;
    }

    // Read the entire file into memory
    fread(buffer, file_size, 1, file);

    // Disassemble all code sections using Capstone
    disassemble_code_sections( section_header_table, num_sections, buffer);

    // Clean up
    free(buffer);
    free(section_header_table);
    fclose(file);

    return 0;
}
void print_5_instr_from_addr(unsigned long long addr){
    std::map<long long, cs_insn>::iterator iter= instructions.find(addr);
    for (int i=0;i<5;i++){
        if (iter==instructions.end()){
            printf("** the address is out of the range of the text section.\n");
            break;
        }
        printf("%12llx: ", iter->first);
        int j ;
        for (j =0 ;j< iter->second.size;j++){
            printf("%02x ",iter->second.bytes[j]);
        }
        for (;j<12;j++){
            printf("   ");
        }
        printf("\t\t%s\t%s\t\n", iter->second.mnemonic,iter->second.op_str);
        iter++;
    }
}
int get_input_cmd(std::vector<std::string>& cmd){
    printf("(sdb) ");
    cmd.clear();
    char line[1024]={0};
    fgets(line,1024,stdin);
    char *token = strtok(line," ");
    while(token != NULL){
        if (token[strlen(token)-1]=='\n'){
            token[strlen(token)-1]=0;
        }
        cmd.insert(cmd.end(),std::string(token));
        token = strtok(NULL, " ");
    }
    return 0;
}

void restore_instr(pid_t child, unsigned long long addr){
    auto it = instructions.find(addr);
    if(it==instructions.end()) return;
    uint64_t originalData = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
    uint64_t newData = (originalData & 0xFFFFFFFFFFFFFF00) |it->second.bytes[0];
    // printf("%llx %llx\n",originalData,newData);
    ptrace(PTRACE_POKETEXT, child, addr, newData); 
}
void cc_instr(pid_t child, unsigned long long addr){
    auto it = instructions.find(addr);
    if(it==instructions.end()) return;
    uint64_t originalData = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
    uint64_t newData = (originalData & 0xFFFFFFFFFFFFFF00) | 0xcc;
    // printf("%llx %llx\n",originalData,newData);
    ptrace(PTRACE_POKETEXT, child, addr, newData); 
}
void step(pid_t child , int* status){

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    unsigned long long prev_rip= regs.rip;
    restore_instr(child,regs.rip);

    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("single step in si");
    waitpid(child,status,0);
    if(!WIFSTOPPED(*status)){
        return;
    }
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    auto it = breakpoints.find(regs.rip);
    if(it!=breakpoints.end()){
        printf("** hit a breakpoint at 0x%llx.\n",regs.rip);
    }

    it = breakpoints.find(prev_rip);
    if(it!=breakpoints.end()){
        cc_instr(child,prev_rip);
    }
    print_5_instr_from_addr(regs.rip);
}
int setBreakpoint(pid_t child, unsigned long long addr){
    auto it = instructions.find(addr);
    if(it == instructions.end()) return -1;

    breakpoints.insert(addr);
    printf("** set a breakpoint at %p.\n",(void*)addr);
    cc_instr(child,addr);
    // originalData = ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
    // printf("%llx\n",originalData);
    return 0;

}
void cont(pid_t child , int *status){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    unsigned long long prev_rip= regs.rip;
    restore_instr(child,regs.rip);

    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("single step in si");
    waitpid(child,status,0);

    ptrace(PTRACE_GETREGS, child, 0, &regs);
    auto it = breakpoints.find(prev_rip);
    if(it!=breakpoints.end()){
        cc_instr(child,prev_rip);
    }
    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child,status,0);
    if(WIFSTOPPED(*status)){
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        it = breakpoints.find(regs.rip-1);
        if(it !=breakpoints.end() ){
            printf("** hit a breakpoint at 0x%llx.\n",regs.rip-1);
        }
        print_5_instr_from_addr(regs.rip-1);
        regs.rip--;
        ptrace(PTRACE_SETREGS,child,0,&regs);
    }

}
void restore_snapshot(pid_t child,snapshot ss){
    unsigned long data;
    if(ptrace(PTRACE_SETREGS, child, 0, &ss.ss_regs)<0) errquit("snapshot register");
    for(int i=0;i<ss.minfos.size();i++){
        range& r = ss.child_infos[i];
        minfo& m = ss.minfos[i];
        for(uint64_t j=0;j<m.size;j+=8){
            uint64_t *ptr =(uint64_t*)(m.start+j);
            ptrace(PTRACE_POKEDATA,child,r.start+j,*ptr);
        }
    }

}
void create_snapshot_storage(snapshot& ss){
    if(ss.used==1) return;
    ss.used=1;
    for (int i =0; i<ss.child_infos.size();i++){
        minfo m;
        m.size = ss.child_infos[i].end-ss.child_infos[i].start;
        m.start = (uint8_t*)malloc(m.size);
        ss.minfos.insert(ss.minfos.end(),m);
    }
}
void delete_snapshot_storage(snapshot& ss){
    if(ss.used==1){
        for (int i =0; i<ss.minfos.size();i++){

            free(ss.minfos[i].start);
            ss.minfos[i].start=0;
            ss.minfos[i].size =0;
        }
        ss.used =0;
    }
}
void take_snapshot(pid_t child,const snapshot &ss){
    uint64_t data;
    if(ptrace(PTRACE_GETREGS, child, 0, &ss.ss_regs)<0) errquit("snapshot register");
    for(int i=0;i<ss.child_infos.size();i++){
        for(uint64_t j=0;j<ss.minfos[i].size;j+=8){
            data = ptrace(PTRACE_PEEKDATA,child,ss.child_infos[i].start+j,NULL);
            memcpy(ss.minfos[i].start+j,&data,8);
        }
    }
}
void anchor(pid_t child,int* status){
    char filename[100]={0};
    char c;
    char buf[0x1000]={0};
    std::vector<range>& store = anchor_snapshot.child_infos;
    store.clear();
    char permit[10]={0};
    snprintf(filename,100,"/proc/%d/maps",child);
    FILE* fp = fopen(filename,"r");
    while(fgets(buf,0x1000,fp)){
        range r;
        sscanf(buf,"%llx %c %llx %s",&r.start,&c,&r.end,permit);
        if(permit[1]=='w'){
            // printf("%s",buf);
            store.insert(store.end(),r);
        }
    }
    delete_snapshot_storage(anchor_snapshot);
    create_snapshot_storage(anchor_snapshot);
    take_snapshot(child,anchor_snapshot);

    printf("** dropped an anchor\n");

}
void timetravel(pid_t child){
    restore_snapshot(child,anchor_snapshot);
    printf("** go back to the anchor point\n");
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, 0, &regs);
    print_5_instr_from_addr(regs.rip);
}
int main(int argc, char *argv[])
{
    if(argc<2){
        fprintf(stderr,"Usage: <%s> <command>", argv[0]);
    }
    readelf_disassemble(argv[1]);
    pid_t child = 0;
    if ((child = fork())<0) errquit("fork");
    if (child ==0 ){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace");
		execvp(argv[1], argv+1);
		errquit("execvp");
    }
    else{
        int status;
        std::vector<std::string> cmd;
        struct user_regs_struct regs;
        anchor_snapshot.used=0;
        setvbuf(stdin, nullptr, _IOLBF, 0);
        if(waitpid(child,&status,0)<0) errquit("wait traceme");
        assert(WIFSTOPPED(status));
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEEXEC);
        
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        uint64_t entry_point = regs.rip; // x86_64 架构的寄存器是 rip
        
        printf("** program './hello' loaded. entry point %lx\n", entry_point);
        print_5_instr_from_addr(entry_point);
        while(WIFSTOPPED(status)){
            get_input_cmd(cmd);
            if(cmd.size()==0){
                break;
            }
            if(cmd[0].compare("si")==0){
                step(child,&status);
            }
            else if(cmd[0].compare("break")==0){
                unsigned long long break_addr = std::stol(cmd[1], nullptr, 16);
                setBreakpoint(child,break_addr);

            }
            else if(cmd[0].compare("cont")==0){
                cont(child,&status);
            }
            else if(cmd[0].compare("anchor")==0){
                anchor(child,&status);
            }
            else if(cmd[0].compare("timetravel")==0){
                timetravel(child);
            }
            else{
                printf("command not found\n");
            }
        }
        // ptrace(PTRACE_CONT, child, 0, 0);
        // waitpid(child, &status, 0);
        if(WIFEXITED(status)){
            printf("** the target program terminated.\n");
        }
        
    }
}