#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>
#include <sys/mman.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <asm/ldt.h>   
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <inttypes.h>
#include <assert.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <keystone/keystone.h>

#include "../include/dryadalis_x86.h"

/*
    is_cflow - checks if an instruction is a control flow instruction
    @group: group to which the instruction belongs
*/
_Bool is_cflow(int group) {
    switch (group) {
        case X86_GRP_CALL:
            return true;
        case X86_GRP_INT:
            return true;
        case X86_GRP_JUMP:
            return true;
        case X86_GRP_RET:
            return true;
        case X86_GRP_BRANCH_RELATIVE:
            return true;
        case X86_GRP_PRIVILEGE:
            return true;
        case X86_GRP_IRET:
            return true;

        default:
            break;
    }

    return false;
}

_Bool curr_syscall;

/* 
    is_ret -  is the instruction a return instruction ?
*/
_Bool is_ret(int group) {
    return (group == X86_GRP_RET);
}


/*
    is_call - is the instruction a call instruction
*/
_Bool is_call(int group) {
    return (group == X86_GRP_CALL);
}

/*
    is_interrupt - is the instruction an interrupt instruction
*/
_Bool is_interrupt(int group) {
    return (group == X86_GRP_INT) || (group == X86_GRP_PRIVILEGE) || (group == X86_GRP_IRET);
}

_Bool is_syscall(int group) {
    return (group == X86_GRP_INT);
}

/*
    opcodes_cflow - returns how many bytes there are up to the next control flow instruction
    @addr: address from which the analysis began
    @s_binary: object descriptor
    @beg: bool set to true when it's called for the first time
    @opt: useless
*/
int opcodes_cflow(uint64_t addr, mdata_binary_t* s_binary, _Bool beg) 
{
    uint8_t insn_buffer[PAGE_SZ] = {0};
    uint64_t saved_addr = addr;
    uint8_t* insn_buf = insn_buffer;

    size_t size = PAGE_SZ;
    size_t saved_size = PAGE_SZ;
    int n = 0;

    if (!is_mapped(addr, s_binary)) {
        fprintf(stderr, "> @opcodes_cflow > @is_mapped: 0x%lx is not mapped\n", addr);
        return -1;
    }

    /* overloapping instruction */
    if (PAGE_OFFT(addr) + INSTRUCTION_MAX_SZ >= PAGE_SZ) {
        /* We work on only on a buffer of PAGE_SZ - PAGE_OFFSET(addr) bytes */
        if (!is_mapped(PAGE_ALIGN(addr) + PAGE_SZ, s_binary)) {
            size = PAGE_SZ - PAGE_OFFT(addr);
        } else {
            size = PAGE_SZ;
        }
    }

    assert(size);

    if (-1 == (saved_size = mem_read(s_binary, insn_buffer, addr, size))) {
        fprintf(stderr, "> @opcodes_cflow: failed to read at %lx\n", addr);
		fatal_dump(s_binary);
    }

    while(n < saved_size && cs_disasm_iter(s_binary->dbi_handler->cps_utils->handle, (const uint8_t **)&insn_buf, &size, &addr, s_binary->dbi_handler->cps_utils->insn)) {
        s_binary->dbi_handler->cps_utils->count++;
        if (DEBUG & LOG_INSN) {
            fprintf(s_binary->debug_stream, 
                    "0x%lx\t%s %s\n", 
                    s_binary->dbi_handler->cps_utils->insn->address, 
                    s_binary->dbi_handler->cps_utils->insn->mnemonic, 
                    s_binary->dbi_handler->cps_utils->insn->op_str
                );
        }

        for (size_t i = 0; i < s_binary->dbi_handler->cps_utils->insn->detail->groups_count; i++) {
            if (is_cflow(s_binary->dbi_handler->cps_utils->insn->detail->groups[i])) {
                if (beg && curr_syscall) {
                    continue;
                } else {
                    return n;
                }
            }
        }

        n += s_binary->dbi_handler->cps_utils->insn->size;
        beg = false;
        curr_syscall = false;
    }

    if (is_mapped((saved_addr + n), s_binary) && n) {
        // if the page next to the current page is mapped we call opcode_cflow onto it
        if (DEBUG & LOG_INSN) {
            fprintf(s_binary->debug_stream, "recurr call, size: %lx, addr: %lx\n", size, saved_addr + n);
        }

        return n + opcodes_cflow(saved_addr + n, s_binary, true);
    }

    fprintf(stderr, "FATAL found nothing\n");
    return -1;
}

/* insn_len - returns the length of the instruction for which target points to
    @target: address of the target instruction
    @s_binary: object descriptor
*/
off_t insn_len(uint64_t target, mdata_binary_t* s_binary) 
{
    csh handle = s_binary->dbi_handler->cps_utils->handle;
    size_t _sz = INSTRUCTION_MAX_SZ;
    uint8_t buf_insn[INSTRUCTION_MAX_SZ] = {0};
    uint8_t* buf = buf_insn;
    uint32_t sz_ret = 0;

    cs_insn* insn_d = cs_malloc(handle);

    if (!is_mapped_range(s_binary, target, INSTRUCTION_MAX_SZ)) {
        fprintf(stderr, "> @ins_len > @is_mapped_range: %lx isn't mapped\n", target);
        fatal_dump(s_binary);
    } else if (-1 == mem_read(s_binary, buf_insn, target, INSTRUCTION_MAX_SZ)) {
        fprintf(stderr, "> @ins_len > @mem_read: from: %lx, size: %x\n", target, INSTRUCTION_MAX_SZ);
        fatal_dump(s_binary);
    }

    if (cs_disasm(handle, buf, _sz, target, 1, &insn_d)) {
        sz_ret = insn_d->size;
        cs_free(insn_d, 1);
        return sz_ret;
    }

    fprintf(stderr, "> @ins_len > @cs_disasm_iter: failed to disassemble at %lx\n", target);
    cs_free(insn_d, 1);
    return -1;
}

/*
    is_jmp_taken - checks if a jmp is taken ot not
    @id: capstone id of the instruction
    @s_binary: object descriptor
*/
_Bool is_jmp_taken(int id, mdata_binary_t* s_binary) 
{
    switch (id) {
        case X86_INS_JE:
            return is_set(s_binary, ZF);
        case X86_INS_JNE:
            return !is_set(s_binary, ZF);
        
        case X86_INS_JA:
            return !is_set(s_binary, CF) && !is_set(s_binary, ZF);
        case X86_INS_JAE:
            return !is_set(s_binary, CF);
    
        case X86_INS_JB:
            return is_set(s_binary, CF);
        case X86_INS_JBE:
            return is_set(s_binary, CF) || is_set(s_binary, ZF);

        case X86_INS_JCXZ:
            return !read_reg(X86_REG_CX, s_binary->dbi_handler->hashmap);
        case X86_INS_JECXZ:
            return !read_reg(X86_REG_ECX, s_binary->dbi_handler->hashmap);
        case X86_INS_JRCXZ:
            return !read_reg(X86_REG_RCX, s_binary->dbi_handler->hashmap);

        case X86_INS_JG:
            return !is_set(s_binary, ZF) && (is_set(s_binary, SF) == is_set(s_binary, OF));
        case X86_INS_JGE:
            return (is_set(s_binary, SF) == is_set(s_binary, OF));

        case X86_INS_JL:
            return (is_set(s_binary, SF) != is_set(s_binary, OF));
        case X86_INS_JLE:
            return is_set(s_binary, ZF) || is_set(s_binary, SF) != is_set(s_binary, OF);

        case X86_INS_JO:
            return is_set(s_binary, OF);
        case X86_INS_JNO:
            return !is_set(s_binary, OF);

        case X86_INS_JP:
            return is_set(s_binary, PF);
        case X86_INS_JNP:
            return !is_set(s_binary, PF);

        case X86_INS_JS:
            return is_set(s_binary, SF);
        case X86_INS_JNS:
            return !is_set(s_binary, SF);

        case X86_INS_JMP:
            return true;

        default:
            fprintf(stderr, "not found cflow\n");
            fatal_dump(s_binary);
            // not reached
            return -1;
    }
}

/*
    is_test - checks if the instruction checks the eflags
    @cs_eflags: capstone eflags
*/
_Bool is_test(uint64_t cs_eflags) 
{
    return (cs_eflags & (X86_EFLAGS_TEST_AF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_IF | X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_TF | X86_EFLAGS_TEST_ZF)) != 0;
}

/*
    is_set - checks if a particular flag is set in the eflags 
*/
_Bool is_set(mdata_binary_t* s_binary, int flag) 
{
    if (DEBUG & LOG_JMP) {
        fprintf(s_binary->debug_stream, "eflags & flag: %lx & %x = %lx\n", read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap), flag, (read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & flag));
    }

    uint64_t eflags = read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap);
    
    if (-1 == eflags) {
        fprintf(stderr, "FATAL read eflags\n");
        fatal_dump(s_binary);
    }

    return (eflags & flag) != 0;
}

/* sign_extend - performs a sig extension according to @size and @value and returns it
    @size: size for the extension
    @value: value we want to extend
*/
long sign_extend(size_t size, uint64_t value) 
{
    return (((value & (1 << ((size*8) - 1))) << (63-(size-1))) | ((value & ~(0 << ((size*8)-1)))));
}


/*
    __eval_target - returns the actual target for the @insn
    @s_binary: object descriptor
    @insn: capstone instruction
    @instruction address
*/
uint64_t __eval_target(cs_insn* insn, mdata_binary_t* s_binary, uint64_t instruction) 
{
    cs_detail* details = insn->detail;
    cs_x86* x86 = &(details->x86);
    _Bool achieve = false;

    for (size_t i = 0; i < details->groups_count; i++) {
        if (details->groups[i] == X86_GRP_JUMP || details->groups[i] == X86_GRP_BRANCH_RELATIVE || is_call(details->groups[i])) {
            if (is_call(details->groups[i]) || is_jmp_taken(insn->id, s_binary)) {
                cs_x86_op* operand = &(x86->operands[0]);

                if (DEBUG & LOG_JMP) {
                    fprintf(s_binary->debug_stream, " taken ");
                }

                if (is_call(details->groups[i]) && !achieve) {
                    // we emulate the call instruction
                    s_binary->dbi_handler->state->rsp -= 8;

                    *(uint64_t* )s_binary->dbi_handler->state->rsp = s_binary->dbi_handler->state->rip + insn->size;
                    achieve = true;
                }

                switch (operand->type) {
                    uint64_t base, index;
                    case X86_OP_REG:
                        return read_reg(operand->reg, s_binary->dbi_handler->hashmap);
                    case X86_OP_IMM:
                        return (uint64_t)(sign_extend(operand->size, operand->imm) + s_binary->dbi_handler->state->rip);
                    case X86_OP_MEM:
                        // no need to perform checks about the sanity of the index, base & segment registers cause if a reg is invalid it will return 0
                        base = read_reg(operand->mem.base, s_binary->dbi_handler->hashmap);
                        if (operand->mem.index != X86_REG_INVALID) {
                            index = read_reg(operand->mem.index, s_binary->dbi_handler->hashmap);
                        } else {
                            index = 0x0;
                        }

                        if (-1 != base && -1 != index) {
                            if (operand->mem.base == X86_REG_RIP) {
                                base += insn->size;
                            }

                            if (DEBUG & LOG_JMP) {
                                fprintf(s_binary->debug_stream, "(base [ %x ] => [ %lx ], index [ %x ] => [ %lx ], scale [ %x ], disp [ %lx ]) => %lx\n", operand->mem.base, base, operand->mem.index, index, operand->mem.scale, operand->mem.disp, (base + (index * operand->mem.scale) + operand->mem.disp));
                            }

                            return *((uint64_t* )(base + index * operand->mem.scale + operand->mem.disp));
                        }

                        fprintf(stderr, "failed to read registers, base [ %x ] => [ %lx ], index [ %x ] => [ %lx ]\n", operand->mem.base, base, operand->mem.index, index);
                        return -1;

                    default:
                        fprintf(stderr, "error operand jmp\n");
                        return -1;
                }
            } else {
                // jmp not taken
                if (DEBUG & LOG_JMP) {
                    fprintf(s_binary->debug_stream, " not taken ");
                }

                return (uint64_t)(instruction + insn->size);
            }
        } else if (is_ret(details->groups[i])) {
            s_binary->dbi_handler->state->rsp += 8;
            return *((uint64_t* )(read_reg(X86_REG_RSP, s_binary->dbi_handler->hashmap)-8));
        } else if (is_syscall(details->groups[i])) {
            hook_syscall sys_callback = NULL;
            uint64_t ret = 0x0;
            size_t sz = insn->size;

            if ((hook_syscall)-1 != (sys_callback = get_syscall_hook(s_binary->dbi_handler->state->rax, s_binary))) {

                if (set_fs_gs((void* )s_binary->dbi_handler->instrumented_fs, (void* )s_binary->dbi_handler->instrumented_gs)) {
                    fprintf(stderr, "FATAL arch_prctl\n");
                }

                ret = sys_callback(s_binary);

                if (set_fs_gs((void* )s_binary->dbi_handler->host_state->fs, (void* )s_binary->dbi_handler->host_state->gs)) {
                    fprintf(stderr, "FATAL arch_prctl\n");
                    fatal_dump(s_binary);
                }

                if (ret) {
                    // if the control flow is broken we jump on a particular location returned by sys_callback when the return value is != 0
                    return ret;
                }

                return (uint64_t)(instruction + sz);
            }

            curr_syscall = true;
            return (uint64_t)(instruction);
        }
    }

    // if that's not a return, a call or a jmp it can be an interrupt and we handle that by a diffrent way so we ignore it for now
    printf("unhandled instruction %lx\n", instruction);
    exit(EXIT_FAILURE);
}

/*
    eval_target - returns the actual target for the control flow instruction @instruction
    @instruction: pointer to the control flow instruction
    @s_binary: object descriptor
*/
uint64_t eval_target(uint8_t* instruction, mdata_binary_t* s_binary) 
{
    char buf_insn[INSTRUCTION_MAX_SZ] = {0};
    uint64_t target = 0;

    if (-1 == mem_read(s_binary, buf_insn, (uint64_t)instruction, INSTRUCTION_MAX_SZ)) {
        fprintf(stderr, "> @eval_target: fail to read @ %lx\n", (uint64_t)instruction);
        return -1;
    }

    s_binary->dbi_handler->cps_utils->count += cs_disasm(s_binary->dbi_handler->cps_utils->handle, (const uint8_t *)buf_insn, 16, 0, 1, &s_binary->dbi_handler->cps_utils->insn);
    target = __eval_target(s_binary->dbi_handler->cps_utils->insn, s_binary, (uint64_t)instruction);

    return target;
}