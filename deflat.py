import angr
import argparse
import os
import logging
from angrutils import *

logging.getLogger('cle').setLevel(logging.DEBUG)
logging.getLogger('angr').setLevel(logging.DEBUG)

# 绘制CFG图
def PlotCFG(proj, name):
    main = proj.loader.main_object.get_symbol('main')
    start_state = proj.factory.blank_state(addr=main.rebased_addr)
    cfg = proj.analyses.CFGFast(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
    plot_cfg(cfg, name, asminist=True, remove_imports=True, remove_path_terminator=True)

# 反混淆虚假控制流
def AntiObfuscate(start_addr):

if __name__ == "__main__":
    # 设定参数
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='File to antiobfuscate')
    parser.add_argument('-s', '--start', type=lambda x : int(x, 0), help='Starting address of target function')
    args = parser.parse_args()
    
    # 读取文件
    proj = angr.Project(args.file, load_options={'auto_load_libs': False})
    start_addr = args.start
    
    PlotCFG(proj, 'Before anti-obfuscation')
    
    # 如果未指定起始地址，则从main函数的地址开始
    if start_addr == None:
        main = proj.loader.find_symbol('main')
        # 如果不存在main
        # 或许可以从_start开始？
        if main == None:
            parser.error("Can't find <main> function, please provide a starting address with -s option")
        start_addr = main.rebased_addr
    
    with open(args.file, 'rb') as file:
        binfile = bytearray(file.read())
        
    AntiObfuscate(start_addr)
    
    fname, ext = os.path.splitext(args.file)
    with open(fname + '_recovered' + ext, 'wb') as file:
        file.write(binfile)
    
    print('Anti-Obfuscate <' + args.file + '> successfully!')