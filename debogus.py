import angr
import argparse
import os
import logging
import struct
from angrutils import *
from angrmanagement.utils.graph import to_supergraph

logging.getLogger('cle').setLevel(logging.ERROR)
logging.getLogger('angr').setLevel(logging.ERROR)

OPCODE_X86 = {'a': b'\x87', 'ae': b'\x83', 'b': b'\x82', 'be': b'\x86', 'c': b'\x82', 'e': b'\x84', 'z': b'\x84', 'g': b'\x8F', 'ge': b'\x8D', 'l': b'\x8C', 'le': b'\x8E', 'na': b'\x86', 'nae': b'\x82', 'nb': b'\x83', 'nbe': b'\x87', 'nc': b'\x83', 'ne': b'\x85', 'ng': b'\x8E', 'nge': b'\x8C', 'nl': b'\x8D', 'nle': b'\x8F', 'no': 'b\x81', 'np': b'\x8B', 'ns': b'\x89', 'nz': b'\x85', 'o': b'\x80', 'p': b'\x8A', 'pe': b'\x8A', 'po': b'\x8B', 's': b'\x88', 'nop': b'\x90', 'jmp': b'\xE9', 'j': b'\x0F'}

# 绘制CFG图
def PlotCFG(proj, name):
    main = proj.loader.main_object.get_symbol('main')
    if main == None:
        parser.error("Can't find <main> function, please provide a starting address with -s option")
    start_state = proj.factory.blank_state(addr=main.rebased_addr)
    cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
    plot_cfg(cfg, name, asminst=True, remove_imports=True, remove_path_terminator=True)

# 转换成IDA Pro的CFG图
def GetCFG(start_addr):
    cfg = proj.analyses.CFGFast(normalize=True, force_complete_scan=False)
    func_cfg = cfg.functions.get(start_addr).transition_graph
    super_cfg = to_supergraph(func_cfg)
    return super_cfg

# Patch掉不可到达的块
def PatchNOP(block):
    offset = block.addr - base_addr
    binfile[offset : offset + block.size] = OPCODE_X86['nop'] * block.size
    print('Patch from %#x to %#x' % (block.addr, block.addr + block.size))

def PatchJMP(block, target_addr):
    inst = block.capstone.insns[-1]
    if inst.mnemonic == 'call':
        return None
    offset = inst.address - base_addr
    binfile[offset : offset + inst.size] = OPCODE_X86['nop'] * inst.size
    binfile[offset : offset + 5] = OPCODE_X86['jmp'] + struct.pack('<I', target_addr - inst.address - 5)
    print('Patch [%s\t%s] at %#x' % (inst.mnemonic, inst.op_str, inst.address))

# 反混淆虚假控制流
def Debogus(start_addr):
    flow = set()
    cfg = GetCFG(start_addr)
    
    flow.add(start_addr)
    
    # 开始符号执行
    state = proj.factory.blank_state(addr=start_addr)
    simgr = proj.factory.simgr(state)
    while len(simgr.active):
        for active in simgr.active:
            flow.add(active.addr)
            block = proj.factory.block(active.addr)
            # hook掉call的函数，随便返回一个值从而限制符号执行的范围
            for inst in block.capstone.insns:
                if inst.mnemonic == 'call':
                    next_func_addr = int(inst.op_str, 16)
                    proj.hook(next_func_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
                    print('Hook [%s\t%s] at %#x' % (inst.mnemonic, inst.op_str, inst.address))
        simgr.step()
        
    # 这里有些问题，在测试素数筛的时候会直接破坏掉循环，还需要修改
    # 在返回为False的不透明谓词的后面会紧跟着跳到alteredBasicBlock，同样也需要Patch掉
    # for block_addr in blocks:
    #     PatchNOP(proj.factory.block(block_addr))
    patch_nodes = set()
    
    for node in cfg.nodes():
        if node.addr in patch_nodes:
            continue
        
        if node.addr not in flow:
            block = proj.factory.block(node.addr)
            PatchNOP(block)
        else:
            suc_nodes = list(cfg.successors(node))
            jmp_targets = []
            
            for suc_node in suc_nodes:
                if suc_node.addr in flow:
                    jmp_targets.append(suc_node.addr)
                else:
                    block = proj.factory.block(suc_node.addr)
                    PatchNOP(block)
                    patch_nodes.add(suc_node.addr)
            
            if len(suc_nodes) and len(jmp_targets) == 1:
                block = proj.factory.block(node.addr)
                PatchJMP(block, jmp_targets[0])

if __name__ == "__main__":
    # 设定参数
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='File to antiobfuscate')
    parser.add_argument('-s', '--start', type=lambda x : int(x, 0), help='Starting address of target function')
    args = parser.parse_args()
    
    # 读取文件
    proj = angr.Project(args.file, load_options={'auto_load_libs': False})
    start_addr = args.start
    
    # PlotCFG(proj, 'Before anti-obfuscation')
    
    # 如果未指定起始地址，则从main函数的地址开始，并且确定main基地址
    if start_addr == None:
        main = proj.loader.find_symbol('main')
        # 如果不存在main，返回错误
        # __start不在当前的object文件中，是链接器添加的
        if main == None:
            parser.error("Can't find <main> function, please provide a starting address with -s option")
        start_addr = main.rebased_addr
        base_addr = proj.loader.main_object.mapped_base
    
    with open(args.file, 'rb') as file:
        binfile = bytearray(file.read())
        
    Debogus(start_addr)
    
    fname, ext = os.path.splitext(args.file)
    with open(fname + '_recovered' + ext, 'wb') as file:
        file.write(binfile)
    
    # proj2 = angr.Project(fname + '_recovered' + ext, load_options={'auto_load_libs': False})
    # PlotCFG(proj2, 'After anti-obfuscation')
    
    print('Anti-Obfuscate-debogus <' + args.file + '> successfully!')