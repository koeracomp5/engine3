
import winappdbg
import inspect
import os
import struct



class Hack(object):

    def __init__(self, processName):
        self.name = processName
        self.hwnd = self.findProcess(processName)
        self.print_info()
        self.vaddr_map = self.get_vaddr_map()
        self.memory_dump_db = None
        self.variable_info_db = None

    def memory_read(self, address, size) :
        return self.hwnd.read(address, size)

    def get_memory_full_dump_db(self) :
        mem_dump_db = dict()
        for base_addr in self.vaddr_map.keys() :
            size = self.vaddr_map[base_addr]
            mem_dump_db[base_addr] = self.memory_read(base_addr, size)
        return mem_dump_db

    def first_scan(self) :
        self.variable_info_db = None
        self.memory_dump_db = self.get_memory_full_dump_db()

    def print_info (self) :
        print "process name : %s" % self.name
        print "module list"
        print "%-70s %12s %12s %12s" % ("name", "base", "size", "ep")
        size = 0
        for item in self.hwnd.iter_modules() :
            m_name = item.get_filename()
            m_base = item.get_base()
            m_size = item.get_size()
            m_ep = item.get_entry_point()
            size += m_size
            print "%-70s %12x %12x %12s" % (m_name, m_base, m_size, None if m_ep == None else hex(m_ep))

        print "memory info"
        commited_page_cnt = 0
        for mbi in self.hwnd.get_memory_map() :
            if mbi.is_commited() :
                cur_module = self.hwnd.get_module_at_address(mbi.BaseAddress)
                if cur_module == None :
                    module_name = "empty"
                else :
                    module_name = cur_module.get_name()
                print "0x%08x %4d %d %d %d %s" % (mbi.BaseAddress, mbi.RegionSize//(2**12), int(mbi.is_readable()), int(mbi.is_writeable()), int(mbi.is_executable()), module_name)
                commited_page_cnt += mbi.RegionSize//(2**12)

        print "total commited memory size : %dbytes" % (commited_page_cnt*(2**12))

    def get_vaddr_map(self) :
        vaddr_map = dict()
        total_size = 0
        for mbi in self.hwnd.get_memory_map() :
            if mbi.is_commited() and mbi.is_writeable() and not mbi.is_guard() :
                vaddr_map[mbi.BaseAddress] = mbi.RegionSize
                total_size += mbi.RegionSize
        print("total non-protected writeable page size : %dbytes" % total_size)
        return vaddr_map

    def __repr__(self):
        return "<Hack instance: %s>" %str(self.name)

    def findProcess(self, processName=None):
        system = winappdbg.System()
        for process in system:
            if process.get_filename() is not None:
                name = process.get_filename().split("\\")[-1]
                if processName is None:
                    self.running.append((name, process.get_pid()))
                else:
                    if name == processName:
                        return process

    def next_scan(self, oper_func) :
        var_db = dict()
        next_full_dump_db = dict()
        var_size = 4
        if self.variable_info_db == None :
            next_full_dump_db = self.get_memory_full_dump_db()
            for base_addr in self.memory_dump_db.keys() :
                var_db[base_addr] = []
            for base_addr in self.memory_dump_db.keys() :
                size = self.vaddr_map[base_addr]
                offset = 0
                while offset+var_size < size :
                    origin_val = struct.unpack("i", self.memory_dump_db[base_addr][offset:offset+var_size])[0]
                    next_val = struct.unpack("i", next_full_dump_db[base_addr][offset:offset+var_size])[0]
                    if oper_func(origin_val, next_val) :
                        var_db[base_addr].append(offset)
                    offset+=1
        else :
            for base_addr in self.variable_info_db.keys() :
                size = self.vaddr_map[base_addr]
                next_dump = self.memory_read(base_addr, size)
                var_db_entry = []
                for offset in self.variable_info_db[base_addr] :
                    origin_val = struct.unpack("i", self.memory_dump_db[base_addr][offset:offset+var_size])[0]
                    next_val = struct.unpack("i", next_dump[offset:offset+var_size])[0]
                    if oper_func(origin_val, next_val) :
                        var_db_entry.append(offset)
                if len(var_db_entry) > 0 :
                    var_db[base_addr] = var_db_entry
                    next_full_dump_db[base_addr] = next_dump
        self.memory_dump_db = next_full_dump_db
        self.variable_info_db = var_db

    def print_scaned_var_info (self) :
        var_size = 4
        var_cnt = 0
        for base_addr in self.variable_info_db.keys() :
            for offset in self.variable_info_db[base_addr] :
                addr = base_addr+offset
                val = struct.unpack("i", self.memory_dump_db[base_addr][offset:offset+var_size])[0]
                print "0x%08x -> %d" % (addr, val)
                var_cnt+=1
        print "total %d variables scaned" % var_cnt


def main () :
    ps = Hack("KakaoTalk.exe")
    ps.first_scan()
    cmd_str = raw_input()
    while "fuck" not in cmd_str :
        if "inc" in cmd_str :
            ps.next_scan(lambda a,b : a<b)
        elif "dec" in cmd_str :
            ps.next_scan(lambda a,b : a>b)
        else :
            ps.next_scan(lambda a,b : a==b)
        ps.print_scaned_var_info()
        cmd_str = raw_input()


    #ps = Hack("notepad.exe")



main ()
