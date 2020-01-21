
import winappdbg
import inspect
import os



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
        for base_addr, size in self.vaddr_map :
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
        vaddr_map = []
        total_size = 0
        for mbi in self.hwnd.get_memory_map() :
            if mbi.is_commited() and mbi.is_writeable() and not mbi.is_guard() :
                vaddr_map.append( (mbi.BaseAddress, mbi.RegionSize) )
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

    def next_scan(self, oper_type) :
        if self.variable_info_db == None :
            next_full_dump_db = self.get_memory_full_dump_db()
            for base


def main () :
    ps = Hack("KakaoTalk.exe")
    ps.first_scan()
    #ps = Hack("notepad.exe")



main ()
