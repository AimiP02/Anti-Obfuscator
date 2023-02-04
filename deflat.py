import angr
import argparse
import os
import logging
from angrutils import *
from angrmanagement.utils.graph import to_supergraph

logging.getLogger('cle').setLevel(logging.ERROR)
logging.getLogger('angr').setLevel(logging.ERROR)

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
    offset = block.addr - proj.loader.main_object.mapped_base
    binfile[offset : offset + block.size] = b'\x90' * block.size
    print('Patch %#x with %d nops' % (block.addr, block.size))

# 反混淆虚假控制流
def AntiObfuscate(start_addr):
    bb_set = set()
    cfg = GetCFG(start_addr)
    for node in cfg.nodes:
        bb_set.add(node.addr)
    
    # 开始符号执行
    state = proj.factory.blank_state(addr=start_addr)
    simgr = proj.factory.simgr(state)
    while len(simgr.active):
        for active in simgr.active:
            # 如果可以到达的话说明是真的控制流，从bb_set中删除
            bb_set.discard(active.addr)
            block = proj.factory.block(active.addr)
            # hook掉call的函数，随便返回一个值从而限制符号执行的范围
            for inst in block.capstone.insns:
                if inst.mnemonic == 'call':
                    next_func_addr = int(inst.op_str, 16)
                    proj.hook(next_func_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
                    print('Hook [%s\t%s] at %#x' % (inst.mnemonic, inst.op_str, inst.address))
        simgr.step()
    for block in bb_set:
        PatchNOP(proj.factory.block(block))

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
    
    # 如果未指定起始地址，则从main函数的地址开始
    if start_addr == None:
        main = proj.loader.find_symbol('main')
        # 如果不存在main，返回错误
        # __start不在当前的object文件中，是链接器添加的
        if main == None:
            parser.error("Can't find <main> function, please provide a starting address with -s option")
        start_addr = main.rebased_addr
    
    with open(args.file, 'rb') as file:
        binfile = bytearray(file.read())
        
    AntiObfuscate(start_addr)
    
    fname, ext = os.path.splitext(args.file)
    with open(fname + '_recovered' + ext, 'wb') as file:
        file.write(binfile)
    
    # proj2 = angr.Project(fname + '_recovered' + ext, load_options={'auto_load_libs': False})
    # PlotCFG(proj2, 'After anti-obfuscation')
    
    print('Anti-Obfuscate <' + args.file + '> successfully!')