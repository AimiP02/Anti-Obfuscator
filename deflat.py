import angr
import argparse
import os
import logging
import struct
import sys
import pyvex
import claripy
from angrutils import *
from angrmanagement.utils.graph import to_supergraph
from collections import defaultdict

logging.getLogger('cle').setLevel(logging.ERROR)
logging.getLogger('angr').setLevel(logging.ERROR)

OPCODE_X86 = {'a': b'\x87', 'ae': b'\x83', 'b': b'\x82', 'be': b'\x86', 'c': b'\x82', 'e': b'\x84', 'z': b'\x84', 'g': b'\x8F', 'ge': b'\x8D', 'l': b'\x8C', 'le': b'\x8E', 'na': b'\x86', 'nae': b'\x82', 'nb': b'\x83', 'nbe': b'\x87', 'nc': b'\x83', 'ne': b'\x85', 'ng': b'\x8E', 'nge': b'\x8C', 'nl': b'\x8D', 'nle': b'\x8F', 'no': 'b\x81', 'np': b'\x8B', 'ns': b'\x89', 'nz': b'\x85', 'o': b'\x80', 'p': b'\x8A', 'pe': b'\x8A', 'po': b'\x8B', 's': b'\x88', 'nop': b'\x90', 'jmp': b'\xE9', 'j': b'\x0F'}

# 转换成IDA Pro的CFG图
def GetSuperCFG(proj, start_addr):
    cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
    func_cfg = cfg.functions.get(start_addr).transition_graph
    super_cfg = to_supergraph(func_cfg)
    return super_cfg

def GetRetnAndPrologue(cfg, start_addr):
    for node in cfg.nodes():
        if cfg.in_degree(node) == 0:
            prologue = node
        if cfg.out_degree(node) == 0 and len(node.out_branches) == 0:
            retn = node
    if prologue is None or prologue.addr != start_addr:
        print('Can\'t find prologue of function \'main\'')
        sys.exit(-1)
    
    return retn, prologue

def GetPredispatcher(cfg):
    global prologue, main_dispatcher
    for node in cfg.predecessors(main_dispatcher):
        if node.addr != prologue.addr:
            pre_dispatcher = node
    return pre_dispatcher
            

def GetRelevantAndNopBlocks(cfg):
    global pre_dispatcher, prologue, retn
    relevant_blocks = []
    nop_blocks = []
    for node in cfg.nodes():
        if cfg.has_edge(node, pre_dispatcher) and node.size > 8:
            relevant_blocks.append(node)
            continue
        if node.addr in (prologue.addr, retn.addr, pre_dispatcher.addr):
            continue
        nop_blocks.append(node)
    return relevant_blocks, nop_blocks

def SymbolicExecution(proj, start_addr, hook_addrs=None, modify_value=None, inspect=False):
    global relevants_blocks
    
    def RetnProcedure(state):
        ip = state.solver.eval(state.regs.ip)
        proj.unhook(ip)
        return
    
    def StatementInspect(state):
        expression = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expression) != 0 and isinstance(expression[0], pyvex.expr.ITE):
            state.scratch.temps[expression[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []
    
    if hook_addrs != None:
        for hook_addr in hook_addrs:
            proj.hook(hook_addr, RetnProcedure, length=5)
    
    state = proj.factory.blank_state(addr=start_addr, remove_options={angr.sim_options.LAZY_SOLVES})
    
    if inspect:
        state.inspect.b('statement', when=angr.BP_BEFORE, action=StatementInspect)
        
    simgr = proj.factory.simulation_manager(state)
    simgr.step()
    
    while len(simgr.active):
        for active in simgr.active:
            if active.addr in [node.addr for node in relevant_blocks]:
                return active.addr
        simgr.step()

def PatchBlockWithNOP(block):
    global base_addr, binfile
    offset = block.addr - base_addr
    binfile[offset : offset + block.size] = OPCODE_X86['nop'] * block.size
    print('Patch from %#X to %#X' % (block.addr, block.addr + block.size))

def PatchInstByJXX(inst, target_addr, cond, inst_offset):
    global binfile
    # if inst.mnemonic == 'mov':
    #     return None
    offset = inst.address - base_addr + inst_offset
    binfile[offset : offset + inst.size] = OPCODE_X86['nop'] * inst.size
    if cond == 'jmp':
        opcode = OPCODE_X86['jmp']
        addr_size = 5
    else:
        opcode = OPCODE_X86['j'] + OPCODE_X86[cond]
        addr_size = 6
    binfile[offset : offset + addr_size] = opcode + struct.pack('<i', target_addr - inst.address - addr_size - inst_offset)
    print('Patch [%s\t%s] to [%s\t%s] at %#x' % (inst.mnemonic, inst.op_str, opcode, struct.pack('<i', target_addr - inst.address - addr_size - inst_offset), inst.address))

def Deflatten(proj, cfg):
    global retn, prologue, main_dispatcher, pre_dispatcher, relevant_blocks, nop_blocks, start_addr, base_addr
    global relevants, relevants_without_retn
    retn, prologue = GetRetnAndPrologue(cfg, start_addr) # 返回块和序言
    main_dispatcher = list(cfg.successors(prologue))[0] # 主分发器
    pre_dispatcher = GetPredispatcher(cfg) # 预处理器
    relevant_blocks, nop_blocks = GetRelevantAndNopBlocks(cfg) # 真实块和需要nop的块
    
    print('*******************relevant blocks************************')
    print('prologue: %#X' % start_addr)
    print('main_dispatcher: %#X' % main_dispatcher.addr)
    print('pre_dispatcher: %#X' % pre_dispatcher.addr)
    print('retn: %#X' % retn.addr)
    print('relevant_blocks:', [hex(node.addr) for node in relevant_blocks])
    
    print('*******************symbolic execution*********************')
    relevants = relevant_blocks
    relevants.append(prologue)
    relevants_without_retn = list(relevants)
    relevants.append(retn)
    
    flow = defaultdict(list)
    patch_insts = {}
    
    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant.addr)
        block = proj.factory.block(relevant.addr, size=relevant.size)
        has_branches = False
        hook_addrs = set([])
        
        for inst in block.capstone.insns:
            if inst.insn.mnemonic.startswith('cmov'):
                if relevant not in patch_insts:
                    patch_insts[relevant] = inst
                    has_branches = True
            elif inst.insn.mnemonic.startswith('call'):
                hook_addrs.add(inst.insn.address)

        if has_branches:
            tmp_addr = SymbolicExecution(proj, relevant.addr, hook_addrs, claripy.BVV(1, 1), True)            
            if tmp_addr != None:
                flow[relevant].append(tmp_addr)

            tmp_addr = SymbolicExecution(proj, relevant.addr, hook_addrs, claripy.BVV(0, 1), True)
            if tmp_addr != None:
                flow[relevant].append(tmp_addr)
        else:
            
            tmp_addr = SymbolicExecution(proj, relevant.addr, hook_addrs)
            if tmp_addr != None:
                flow[relevant].append(tmp_addr)
                
    print('************************flow******************************')
    for k, v in flow.items():
        print('%#x: ' % k.addr, [hex(child) for child in v])
    print('%#x: ' % retn.addr, [])
    
    print('************************patch*****************************')
    for nop_block in nop_blocks:
        PatchBlockWithNOP(nop_block)
        
    for parent, childs in flow.items():
        if len(childs) == 1:
            parent_block = proj.factory.block(parent.addr, size=parent.size)
            PatchInstByJXX(parent_block.capstone.insns[-1], childs[0], 'jmp', 0)
        else:
            inst = patch_insts[parent]
            PatchInstByJXX(inst, childs[0], inst.mnemonic[len('cmov'):], 0)
            PatchInstByJXX(inst, childs[1], 'jmp', 6)
            
        

def main():
    global binfile
    global retn, prologue, main_dispatcher, pre_dispatcher, relevant_blocks, nop_blocks, start_addr, base_addr, args
    # 设定参数
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='File to antiobfuscate')
    parser.add_argument('-s', '--start', type=lambda x : int(x, 0), help='Starting address of target function')
    args = parser.parse_args()
    
    proj = angr.Project(args.file, load_options={'auto_load_libs': False})
    start_addr = args.start
    
    # 如果未指定起始地址，则从main函数的地址开始，并且确定main基地址
    if start_addr == None:
        main = proj.loader.find_symbol('main')
        # 如果不存在main，返回错误
        # __start不在当前的object文件中，是链接器添加的
        if main == None:
            parser.error("Can't find <main> function, please provide a starting address with -s option")
        start_addr = main.rebased_addr
        base_addr = proj.loader.main_object.mapped_base
    
    cfg = GetSuperCFG(proj, start_addr)
    
    with open(args.file, 'rb') as file:
        binfile = bytearray(file.read())
        
    Deflatten(proj, cfg)
    
    fname, ext = os.path.splitext(args.file)
    with open(fname + '_recovered' + ext, 'wb') as file:
        file.write(binfile)
    
    print('Anti-Obfuscate-deflatten <' + args.file + '> successfully!')

if __name__ == "__main__":
    main()