
''' Android Memory v2 with updated multiprocessing '''
import json
import sys
import time
import datetime
import math
import pickle
from multiprocessing import Pool, Manager, Process
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.utils as utils
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.psaux as linux_psaux
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.psenv as linux_psenv
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.bash as linux_bash
import volatility.plugins.linux.bash_hash as linux_bash_hash
import volatility.plugins.linux.netstat as linux_netstat
import volatility.plugins.linux.list_raw as linux_list_raw
import volatility.plugins.linux.library_list  as linux_library_list
import volatility.plugins.linux.check_modules as linux_check_modules
import volatility.plugins.linux.hidden_modules as linux_hidden_modules
sys.path.append('../')
from log_handler import nmr_logger
import os

logger = nmr_logger.NMRLogger(platform="Linux", module="android", subModule="memoryAnalysis")
sample_fingerprint = None

class LinuxNetStat:
    """
    Encapsulates the data found for Netstat for a Linux Process
    """
    def __init__(self):
        self.proto = str()
        self.saddr = str()
        self.sport = int()
        self.daddr = str()
        self.dport = int()
        self.state = str()
        self.comm = str()
        self.pid = -1
        self.name = str()

class LinuxNetStatAux:
    def __init__(self):
        self.proto = str()
        self.saddr = str()
        self.sport = int()
        self.daddr = str()
        self.dport = int()
        self.state = str()
        self.comm = str()
        self.pid = -1
        self.name = str()

class LinuxBashHash:
    """
    Encapsulates data found for a Linux Bash Hash for a Linux Process
    """
    def __init__(self):
        self.pid = -1
        self.comm = str()
        self.times_found = -1
        self.command = str()
        self.path = str()


class LinuxBashHistory:
    """
    Encapsulates data found for the bash History for a Linux Process
    """
    def __init__(self):
        self.pid = -1
        self.comm = -1
        self.time = str()
        self.command = str()


class LinuxFileDescriptor:
    """
    Encapsulates the data found in File Descriptors for a Linux Process
    """
    def __init__(self):
        self.objOffset = -1
        self.comm = str()
        self.pid = -1
        self.fileDescriptor = -1
        self.filePath = str()


class LinuxFileProcMapEntry:
    """
    Encapsulates data in a Linux Process Map for a Linux Process
    """
    def __init__(self):
        self.offset = str()
        self.pid = -1
        self.comm = str()
        self.start = -1
        self.end = -1
        self.flags = str()
        self.pageOffset = -1
        self.major = -1
        self.minor = -1
        self.inode = -1
        self.filePath = str()

class LinuxFileProcMap:
    def __init__(self):
        self.offset = str()
        self.pid = -1
        self.start = -1
        self.end = -1
        self.flags = str()
        self.pageOffset = -1
        self.major = -1
        self.minor = -1
        self.inode = -1
        self.filePath = str()

class LinuxProcess:
    """
    Encapsulates all data that may be extracted for a Linux Process using Volatility.
    """
    def __init__(self):
        self.offset = str()
        self.comm = str() # the name of the process
        self.pid = -1 # process ID
        self.ppid = -1 # parent process ID
        self.uid = -1 # used ID
        self.gid = -1 # group ID
        self.dtbAddress = -1 # data tanslation Block address
        self.startTime = 0 # start time of the process
        self.commandLineAux = str() # commandline of the process as found using psaux plugin
        self.commandLineMaps = str() # commandline maps
        self.envVar = str() # environment of the process as found by psenv plugin
        self.procMapEntries = list()  # type: Dict[int:LinuxFileProcMapEntry]
        self.fileDescriptors = list()  # type: List[LinuxFileDescriptor]
        self.bashHistory = list()  # type: List[LinuxBashHistory]
        self.bashHash = list()  # type: List[LinuxBashHash]
        self.heurScore = 0 # the heuristics score assigned to the process
        self.heurList = list()  # type: List[str()]
        self.netstat = list()  # type: List[LinuxNetStat]
        self.isKernelThread = False # is the process a kernel thread
        self.bashEnv = str() # has the bash env if the process contains a bash
        self.log = list()  # type: List[str()]
        self.grabbingRawNet = False # whether the process was capturing raw packets
        self.libList = list()  # type: List[str(())]
        self.jsonLog = dict() # the heuristics log in JSON format
        # self.auxJsonLog = dict() # the log of process details in JSON format
        

class MemoryAnalysisLinux:
    """
    Acts as the controller of the Analysis Procedure. Encapsulates Configuration, process list, heuristics, and Report
    Formats.
    """
    def __init__(self):
        self.log = list()
        self.pids = []
        self.jsonLog = dict()   # included now
        self.processes = dict()  # type: Dict[int:LinuxProcess]
        registry.PluginImporter()
        self.config = conf.ConfObject()
        registry.register_global_options(self.config, commands.Command)
        self.the_file = "file:///home/ronald/volatilityNix/ram.lime"
        self.report = "report.txt"
        base_conf = {'profile': 'LinuxGoldfishx64',
                     'use_old_as': None,
                     'kdbg': None,
                     'help': False,
                     'kpcr': None,
                     'tz': None,
                     'pid': None,
                     'output_file': None,
                     'physical_offset': None,
                     'conf_file': None,
                     'dtb': None,
                     'output': None,
                     'info': None,
                     'location': self.the_file,
                     'plugins': None,
                     'debug': None,
                     'cache_dtb': True,
                     'filename': None,
                     'cache_directory': None,
                     'verbose': None, 'write': False}
        for k, v in base_conf.items():
            self.config.update(k, v)
        self.addr_space = None

        self.androidDict={
            "7.0": ("Linuxgoldfish-7_0-3_10_0x64","Android7.0lib.txt"),
            "10.0": ("Linuxgoldfish-10_0-4_14_150x64", "Android10.0lib.txt"),
            "9.0": ("Linuxgoldfish-9_0x64", "Android9.0lib.txt")
        }
    def runPsList(self):
        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run :: getProcessInfo :: runPsList")
        print("running pslist")
        psList_dict = dict()
        p = linux_pslist.linux_pslist(self.config)
        for (i, [task_offset, comm, pid, ppid, uid, gid, dtb, start_time]) in p.generator(p.calculate()):
            lp = LinuxProcess()
            lp.offset = task_offset
            lp.comm = comm
            lp.pid = pid
            lp.ppid = ppid
            lp.uid = uid
            lp.gid = gid
            lp.dtb = dtb
            lp.start_time = start_time
            psList_dict[lp.pid] = lp
        # print("data of pslist printed",psList_dict)
        pickle_path = 'pslist.txt'
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(psList_dict,fpi)
        # return psList_dict

    def runBash(self):
        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run :: getProcessInfo :: runBash")
        print("running bash")
        bash_dict = dict()
        p = linux_bash.linux_bash(self.config)
        for (i, [pid, comm, time, command]) in p.generator(p.calculate()):
            lbh = LinuxBashHistory()
            lbh.pid = pid
            lbh.comm = comm
            lbh.command = command
            lbh.time = time
            # bash_dict[lbh.pid] = (lbh.__dict__)
            if pid in bash_dict:
                bash_dict[pid].append(lbh.__dict__)
            else:
                bash_dict[pid] = [lbh.__dict__]
        # print("---",bash_dict)
        pickle_path = 'bash.txt'
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(bash_dict,fpi)
        # return psList_dict

    def runBash_hash(self):
        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run :: getProcessInfo :: runBash_hash")
        print("running bash hash")
        bash_hash_dict = dict()
        p = linux_bash_hash.linux_bash_hash(self.config)
        for (i, [pid, comm, times_found, command, path]) in p.generator(p.calculate()):
            lbhash = LinuxBashHash()
            lbhash.pid = pid
            lbhash.comm = comm
            lbhash.times_found = times_found
            lbhash.command = command
            lbhash.path = path
            # bash_hash_dict[lbhash.pid] = (lbhash.__dict__)
            if pid in bash_hash_dict:
                bash_hash_dict[pid].append(lbhash.__dict__)
            else:
                bash_hash_dict[pid] = [lbhash.__dict__]
        # print("----",bash_hash_dict)
        pickle_path = 'bash_hash.txt'
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(bash_hash_dict,fpi)

    def runProcMapEntries(self):
        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run :: getProcessInfo :: runProcMapEntries")
        print("running procmap entries")
        procMapEntries_dict = dict()
        p = linux_proc_maps.linux_proc_maps(self.config)
        for (i, [offset, pid, comm, start, end, flags, pageOffset, major, minor, inode, filePath]) in p.generator(
                p.calculate()):
            pme = LinuxFileProcMapEntry()
            pme.pageOffset = offset
            pme.pid = pid
            pme.comm = comm
            pme.start = start
            pme.end = end
            pme.flags = flags
            pme.pageOffset = pageOffset
            pme.major = major
            pme.minor = minor
            pme.inode = inode
            pme.filePath = filePath
            # procMapEntries_dict[pid] = (pme.__dict__)
            if pid in procMapEntries_dict:
                procMapEntries_dict[pid].append(pme.__dict__)
            else:
                procMapEntries_dict[pid] = [pme.__dict__]
        # print("----",procMapEntries_dict)
        pickle_path = 'proc_map.txt'
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(procMapEntries_dict,fpi)

    """ def runProcMap(self):
        print("running proc map")
        procMap_dict = dict()
        p = linux_proc_maps.linux_proc_maps(self.config)
        for (i, [offset, pid, comm, start, end, flags, pageOffset, major, minor, inode, filePath]) in p.generator(p.calculate()):
            pm = LinuxFileProcMap()
            pm.offset = offset
            pm.pid = pid
            pm.start = start
            pm.end = end
            pm.flags = flags
            pm.pageOffset = pageOffset
            pm.major = major
            pm.minor = minor
            pm.inode = inode
            pm.filePath = filePath
            # procMap_dict[pid] = (pm.__dict__)
            if pid in procMap_dict:
                procMap_dict[pid].append(pm.__dict__)
            else:
                procMap_dict[pid] = [pm.__dict__]
        # print("----",procMap_dict)
        pickle_path = 'testing7.txt'
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(procMap_dict,fpi) """

    """ def runNetstatAux(self):
        print("running netstatAux")
        netstat_aux_dict = dict()
        p = linux_netstat.linux_netstat(self.config)
        for (i, [proto, saddr, sport, daddr, dport, state, comm, pid, name]) in p.generator(p.calculate()):
            lnsaux = LinuxNetStatAux()
            pid = int(pid)
            lnsaux.proto = proto
            lnsaux.saddr = saddr
            lnsaux.sport = sport
            lnsaux.daddr = daddr
            lnsaux.dport = dport
            lnsaux.state = state
            lnsaux.comm = comm
            lnsaux.pid = int(pid)
            lnsaux.name = name
            # netstat_aux_dict[pid] = (lnsaux.__dict__)
            if pid in netstat_aux_dict:
                netstat_aux_dict[pid].append(lnsaux.__dict__)
            else:
                netstat_aux_dict[pid] = [lnsaux.__dict__]
        # print(netstat_aux_dict)
        pickle_path = 'testing8.txt'
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(netstat_aux_dict,fpi) """


    def runNetstat(self):
        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run :: getProcessInfo :: runNetstat")
        print("running netstat")
        pickle_path = 'netstat.txt'
        netstat_list = {}
        p = linux_netstat.linux_netstat(self.config)
        for (i, [proto, saddr, sport, daddr, dport, state, comm, pid, name]) in p.generator(p.calculate()):
            lns = LinuxNetStat()
            pid = int(pid)
            lns.proto = proto
            lns.saddr = saddr
            lns.sport = sport
            lns.daddr = daddr
            lns.dport = dport
            lns.state = state
            lns.comm = comm
            lns.pid = int(pid)
            lns.name = name
            if pid in netstat_list:
                netstat_list[pid].append(lns.__dict__)
            else:
                netstat_list[pid] = [lns.__dict__]
        # print(netstat_list)
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(netstat_list,fpi)


    def runls_of(self):
        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run :: getProcessInfo :: runls_of")
        print("running ls_of")
        ls_of_dict = dict()
        p = linux_lsof.linux_lsof(self.config)
        for (i, [offset, comm, pid, fd, fpath]) in p.generator(p.calculate()):
            lfd = LinuxFileDescriptor()
            lfd.objOffset = offset
            lfd.comm = comm
            lfd.pid = pid
            lfd.fd = fd
            lfd.filePath = fpath
            # ls_of_dict[pid] = (lfd.__dict__)
            if pid in ls_of_dict:
                ls_of_dict[pid].append(lfd.__dict__)
            else:
                ls_of_dict[pid] = [lfd.__dict__]
        # print(ls_of_dict)
        pickle_path = 'ls_of.txt'
        with open(pickle_path, 'wb') as fpi:
            pickle.dump(ls_of_dict,fpi)

    def getProcessInfo(self, androidVersion, reportFile):
        '''
        Loads all the process related information from the ram dump file using the volatility framework
        into the LinuxProcess class. Most of the portions are self explanatory.

        Method includes exception handling and LinuxProcess class instantiation code for every block of
        plugin use.
        '''

        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        procmapEntriesProcess = Process(target=self.runProcMapEntries())
        pslistProcess = Process(target=self.runPsList())
        bashProcess = Process(target=self.runBash())
        bash_hashProcess = Process(self.runBash_hash())
        lsofProcess = Process(target=self.runls_of())
        netstatProcess = Process(target=self.runNetstat())
        logger.debug(sample_hash=sample_fingerprint, message="parallel processes created", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        
        procmapEntriesProcess.start()
        pslistProcess.start()
        
        
        pslistProcess.join()
        logger.debug(sample_hash=sample_fingerprint, message="pslist started", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("pslist joined")
        # self.runPsList()
        with open('pslist.txt', 'rb') as fp:
            lp = pickle.load(fp)
        if os.path.exists('pslist.txt'):
            os.remove('pslist.txt')
        # print("--",lp)
        self.processes = lp
        logger.debug(sample_hash=sample_fingerprint, message="pslist merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("pslist merged")

        '''
        # p = linux_pslist.linux_pslist(self.config)
        # for (i, [task_offset, comm, pid, ppid, uid, gid, dtb, start_time]) in p.generator(p.calculate()):
        #     lp = LinuxProcess()
        #     lp.offset = task_offset
        #     lp.comm = comm
        #     lp.pid = pid
        #     lp.ppid = ppid
        #     lp.uid = uid
        #     lp.gid = gid
        #     lp.dtb = dtb
        #     lp.start_time = start_time
        #     self.processes[lp.pid] = lp
        '''

        try:
            logger.debug(sample_hash=sample_fingerprint, message="running psaux", event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print("running psaux")
            p = linux_psaux.linux_psaux(self.config)
            for (i, [cmdline, pid, uid, gid]) in p.generator(p.calculate()):
                # print(cmdline)
                if pid not in self.processes.keys() : # if the process is not yet in the processes list
                    lp = LinuxProcess()
                    lp.pid = pid
                    lp.uid = uid
                    lp.gid = gid
                    self.processes[pid] = lp
                self.processes[pid].commandLineAux = cmdline.decode('utf-8',errors='ignore')
            logger.debug(sample_hash=sample_fingerprint, message="psaux merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print("psaux merged")
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="psaux exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)

        try:
            logger.debug(sample_hash=sample_fingerprint, message="running psenv", event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print("running psenv")
            p = linux_psenv.linux_psenv(self.config)
            for (i, [comm, pid, env]) in p.generator(p.calculate()):
                if pid not in self.processes.keys() : # if the process is not yet in the processes list
                    lp = LinuxProcess()
                    lp.pid = pid
                    lp.comm = comm
                    self.processes[pid] = lp
                # since the data to be copied to the dictionary is in str format therefore converting or decoding it t utf-8 and ignoring
                self.processes[pid].envVar = env.decode('utf-8',errors='ignore')
            logger.debug(sample_hash=sample_fingerprint, message="psenv merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print("psenv merged")
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="psenv exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)


        bashProcess.start()
        bash_hashProcess.start()

        bashProcess.join()
        logger.debug(sample_hash=sample_fingerprint, message="bash process joined", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("bash process joined")
        try:
            # self.runBash()
            with open('bash.txt', 'rb') as fp:
                lbh = pickle.load(fp)
            if os.path.exists('bash.txt'):
                os.remove('bash.txt')
            # print(lbh)
            for pid,values in lbh.items():
                if pid not in self.processes.keys():
                    lp = LinuxProcess()
                    lp.pid = pid
                    self.processes[pid] = lp
                self.processes[pid].bashHistory  = self.processes[pid].bashHistory + values
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="bash process exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)
        logger.debug(sample_hash=sample_fingerprint, message="bash process merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("bash process merged")


        bash_hashProcess.join()
        logger.debug(sample_hash=sample_fingerprint, message="bash hash process joined", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("bash hash process joined")
        try:
            # self.runBash_hash()
            with open('bash_hash.txt', 'rb') as fp:
                lbhash = pickle.load(fp)
            if os.path.exists('bash_hash.txt'):
                os.remove('bash_hash.txt')
            # print(lbhash)
            for pid,values in lbhash.items():
                if pid not in self.processes.keys():
                    lp = LinuxProcess()
                    lp.pid = pid
                    self.processes[pid] = lp
                self.processes[pid].bashHash = self.processes[pid].bashHash + values
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="bash hash process exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)
        logger.debug(sample_hash=sample_fingerprint, message="bash hash process merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("bash hash process merged")
        

        lsofProcess.start()
        netstatProcess.start()


        lsofProcess.join()
        logger.debug(sample_hash=sample_fingerprint, message="ls_of process joined", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("ls_of process joined")
        try:       
            # self.runls_of()
            with open('ls_of.txt', 'rb') as fp:
                lfd = pickle.load(fp)
            if os.path.exists('ls_of.txt'):
                os.remove('ls_of.txt')
            # print(lfd)
            for pid,values in lfd.items():
                if pid not in self.processes.keys() : # if the process is not yet in the processes list
                    lp = LinuxProcess()
                    lp.pid = pid
                    self.processes[pid] = lp
                self.processes[pid].fileDescriptors = self.processes[pid].fileDescriptors + values
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="ls_of process exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)
        logger.debug(sample_hash=sample_fingerprint, message="ls_of process merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("ls_of process merged")


        netstatProcess.join()
        logger.debug(sample_hash=sample_fingerprint, message="netstat process joined", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("netstat process joined")
        try:
            # self.runNetstat()
            with open('netstat.txt', 'rb') as fp:
                lns = pickle.load(fp)
            if os.path.exists('netstat.txt'):
                os.remove('netstat.txt')
            # print(lns)
            # print(json.dumps(lns,indent=4))
            for pid,values in lns.items():
                # print("---",pid,"---",values)
                if pid not in self.processes.keys():
                    lp = LinuxProcess()
                    lp.pid = pid
                    self.processes[pid] = lp
                self.processes[pid].netstat = self.processes[pid].netstat + values
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="netstat process exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)
        logger.debug(sample_hash=sample_fingerprint, message="netstat process merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("netstat process merged")


        try:
            logger.debug(sample_hash=sample_fingerprint, message="library list running", event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print("library list running")
            p = linux_library_list.linux_library_list(self.config)
            for (i, [comm, pid, l_addr, l_name]) in p.generator(p.calculate()):
                if pid not in self.processes.keys(): # if the process is not yet in the processes list
                    lp = LinuxProcess()
                    lp.pid = pid
                    lp.comm = comm
                    self.processes[pid] = lp
                self.processes[pid].libList.append(l_name)
                # print("---libbbbb----",i)
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="library list exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)
        logger.debug(sample_hash=sample_fingerprint, message="library list merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("library list merged")


        try:
        # ns_dname X 2
            logger.debug(sample_hash=sample_fingerprint, message="list_raw running", event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print("running list_raw")
            p = linux_list_raw.linux_list_raw(self.config)
            for (t, fd, inum) in p.calculate():
                # print("t--",t)
                if t is not None and t in self.processes.keys():
                    if pid not in self.processes.keys(): # if the process is not yet in the processes list
                        lp = LinuxProcess()
                        lp.pid = pid
                        self.processes[pid] = lp
                    self.processes[t.pid].grabbingNet = True
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="list_raw exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)
        logger.debug(sample_hash=sample_fingerprint, message="list_raw merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("list_raw merged")

        
        procmapEntriesProcess.join()
        logger.debug(sample_hash=sample_fingerprint, message="proc map entries joined", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("proc map entries joined")
        try:
            # self.runProcMapEntries()
            with open('proc_map.txt', 'rb') as fp:
                pme = pickle.load(fp)
            if os.path.exists('proc_map.txt'):
                os.remove('proc_map.txt')
            for pid,values in pme.items():
                if pid not in self.processes.keys():
                    lp = LinuxProcess()
                    lp.pid = pid
                    # lp.comm = comm
                    self.processes[pid] = lp
                self.processes[pid].procMapEntries = self.processes[pid].procMapEntries + values
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="proc map entries exception :: "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
            print(e)
        logger.debug(sample_hash=sample_fingerprint, message="proc map entries merged", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        print("proc map entries merged")
        

        # try:
            # self.runProcMap()
        #     with open('testing7.txt', 'rb') as fp:
        #         pm = pickle.load(fp)
        #     for k,v in pm.items():
        #         if "procMap" not in self.processes[k].auxJsonLog.keys():
        #             self.processes[k].auxJsonLog["procMap"] = list()
        #         self.processes[k].auxJsonLog["procMap"].append(v)
        # except Exception as e:
        #     print(e)

        
        # try:
        #     self.runNetstatAux()
        #     with open('testing8.txt', 'rb') as fp:
        #         netstat_aux = pickle.load(fp)
        #     # print(netstat_aux)
        #     for k,v in netstat_aux.items():
        #         if "netstat" not in self.processes[k].auxJsonLog.keys():
        #             self.processes[k].auxJsonLog["netstat"] = list()
        #         self.processes[k].auxJsonLog["netstat"].append(v)
        # except Exception as e:
        #     print(e)
        
        """ CODE IS NOT USED ANYWHERE @Codesaksham 2024-03-28"""
        """ ktpid = -1
        for process in self.processes.values():
            if process.comm == 'kthreadd':
                ktpid = process.pid
                break
        # shared library heuristic
        # load all usual shared libraries
        with open(self.androidDict[androidVersion][1]) as f:
            usualSharedLibs = f.readlines()
        usualSharedLibs = [x.strip() for x in usualSharedLibs] """

        # rootkits in kernel
        # check for kernel modulesls
        
        logger.debug(sample_hash=sample_fingerprint, message="starting json log kernel_modules_discrepancy", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        p = linux_check_modules.linux_check_modules(self.config)
        for (i, [t1, t2]) in p.generator(p.calculate()):
            if t1 != 0:
                self.jsonLog["kernel_modules_discrepancy"] = "{0}-{1}".format(t2, t1)
        logger.debug(sample_hash=sample_fingerprint, message="json log kernel_modules_discrepancy done", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        
        # # hidden modules
        logger.debug(sample_hash=sample_fingerprint, message="starting json log kernel_modules_hidden", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        p = linux_hidden_modules.linux_hidden_modules(self.config)
        for (i, [addr, name]) in p.generator(p.calculate()):
            self.jsonLog["kernel_modules_hidden"] = "{0}-{1}".format(name, addr)
        logger.debug(sample_hash=sample_fingerprint, message="json log kernel_modules_hidden done", event="MemoryAnalysisLinux :: run :: getProcessInfo")

        # preload entries unable to checkl        
        # config.update('find', '/etc/ld.so.preload')
        # p = linux_find_file.linux_find_file(config)
        # for (i, j) in p.calculate():
        # print(i, j)
        
        # #print(self.processes)
        # #print(__dict__(self.processes)
        
        
        logger.debug(sample_hash=sample_fingerprint, message="starting adding processes", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        self.processes_1 = dict()
        for p in self.processes.values():
            # p.encode('utf-8').strip()
            self.processes_1[p.__dict__['pid']]={}                         # Used to convert any list or string to dictionary
            self.processes_1[p.__dict__['pid']]=p.__dict__
        logger.debug(sample_hash=sample_fingerprint, message="processes adding done", event="MemoryAnalysisLinux :: run :: getProcessInfo")

        logger.debug(sample_hash=sample_fingerprint, message="starting file creation", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        logger.debug(sample_hash=sample_fingerprint, message="CHECK LOG", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        try:
            logger.debug(sample_hash=sample_fingerprint, message="INSIDE TRY BLOCK", event="MemoryAnalysisLinux :: run :: getProcessInfo")
            with open(reportFile,'w') as files:
                logger.debug(sample_hash=sample_fingerprint, message="INSIDE TRY BLOCK :: INSIDE WITH", event="MemoryAnalysisLinux :: run :: getProcessInfo")
                json.dump(self.processes_1,files, indent=4)
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="file creation ERROR "+e, event="MemoryAnalysisLinux :: run :: getProcessInfo")
        logger.debug(sample_hash=sample_fingerprint, message="file creation done", event="MemoryAnalysisLinux :: run :: getProcessInfo")
        # with open(reportFile,'w') as files:
        #     try:
        #         json.dump(self.processes_1,files, indent=4)
        #     except Exception as e:
        #         print(e)
        #         files.write(str(self.processes_1).decode('utf-8',errors='ignore'))
        
    
        
    def run(self, the_file, android_version, report_File,pids=None):
        """
        Creates the configuration for Volatility 2.
        Controls the program flow among the methods.

        :param the_file: path to the memory file
        :param the_profile: The volatility profile name to be used with the memory
        :param reportFile: path to the report file to be written into
        :param pids: list of pids to gather data about
        """
        logger.debug(sample_hash=sample_fingerprint, message="started", event="MemoryAnalysisLinux :: run")
        try:
            self.config.update('location', the_file)
            self.config.update('profile', self.androidDict[android_version][0])
            self.addr_space = utils.load_as(self.config)
            logger.debug(sample_hash=sample_fingerprint, message="parameter updated", event="MemoryAnalysisLinux :: run")
            logger.debug(sample_hash=sample_fingerprint, message="getProcessInfo starting", event="MemoryAnalysisLinux :: run")
            self.getProcessInfo(androidVersion=android_version, reportFile = report_File)
            logger.debug(sample_hash=sample_fingerprint, message="exited gracefully", event="MemoryAnalysisLinux :: run")
        except Exception as e:
            logger.error(sample_hash=sample_fingerprint, message="exited with exception "+e, event="MemoryAnalysisLinux :: run")
            empty_dict = str({})
            with open(report_File,'w') as files:
                files.write(empty_dict)
        

# mal = MemoryAnalysisLinux()
# t0 = time.clock()
# output_file = "report_testing"
# intermediate_json = 'memory.json'
# # mal.run(the_file = "file://Lime_files/ram7.0.lime", android_version="7.0", report_File = "report7.0.txt")
# # mal.run(the_file = "file://Lime_files/ram9.0.lime", android_version="9.0", report_File = "report9.0.txt")
# # mal.run(the_file = "file://Lime_files/ram10.0.lime", android_version="10.0", report_File = "report10.0.json")
# mal.run(the_file = "file://Ram_dumps/4bdb7d2d6c575f1ef640dce0338fdc72_ram_dump.lime", android_version="9.0", report_File = "netstat1.json")
# # os.system("7z a " + output_file + " " + intermediate_json)
# t1 = time.clock() - t0
# print("Total time elapsed",t1) 

# if __name__ == "__main__":
# 	input_file = "file://" + sys.argv[1]
# 	output_file = sys.argv[2]
# 	intermediate_json = 'memory.json'
# 	try:
# 		mal = MemoryAnalysisLinux()
# 		#mal.run(the_file = "file://Lime_files/ram7.0.lime", android_version="7.0", report_File = "report7.0.txt")
# 		mal.run(the_file = input_file, android_version="9.0", report_File = intermediate_json)
# 		#mal.run(the_file = "file://Lime_files/ram10.0.lime", android_version="10.0", report_File = "report10.0.json")
# 		os.system("7z a " + output_file + " " + intermediate_json)
# 		#os.remove(intermediate_json)
# 	except Exception as e:
# 		sys.exit("some error occurred" + str(e))
# 	sys.exit(None)


if __name__ == "__main__":
    print("0",sys.argv[0])
    print("1",sys.argv[1])
    print("2",sys.argv[2])
    print("3",sys.argv[3])

    sample_fingerprint = sys.argv[1]
    input_file = "file://" + sys.argv[2]
    output_file = sys.argv[3]
    intermediate_json = 'memory.json'
    logger.debug(sample_hash=sample_fingerprint, message="Memory Analysis started with params sample_fingerprint::"+sample_fingerprint+", input_file::"+input_file+", output_file::"+output_file+", intermediate_json::"+intermediate_json+" with current working dir :: "+os.getcwd(), event="MemoryAnalysisLinux main")
    try:
        if os.path.exists(sys.argv[2]):
            logger.debug(sample_hash=sample_fingerprint, message="Memory dump present", event="MemoryAnalysisLinux main")
            mal = MemoryAnalysisLinux()
            #mal.run(the_file = "file://Lime_files/ram7.0.lime", android_version="7.0", report_File = "report7.0.txt")
            logger.debug(sample_hash=sample_fingerprint, message="MemoryAnalysisLinux Object created", event="MemoryAnalysisLinux main")
            mal.run(the_file = input_file, android_version="9.0", report_File = intermediate_json)
            logger.debug(sample_hash=sample_fingerprint, message="run exited", event="MemoryAnalysisLinux main")
            #mal.run(the_file = "file://Lime_files/ram10.0.lime", android_version="10.0", report_File = "report10.0.json")
            logger.debug(sample_hash=sample_fingerprint, message="Zipping the intermediate json", event="MemoryAnalysisLinux main")
            if os.path.exists(intermediate_json):
                logger.debug(sample_hash=sample_fingerprint, message="intermediate json present creating the zipped memory_raw_result", event="MemoryAnalysisLinux main")
            else:
                logger.error(sample_hash=sample_fingerprint, message="intermediate json NOT present creating the zipped ERROR memory_raw_result", event="MemoryAnalysisLinux main")
                intermediate_json = 'error.json'
            os.system("7z a " + output_file + " " + intermediate_json)
            print("7z a " + output_file + " " + intermediate_json)
            logger.debug(sample_hash=sample_fingerprint, message="7z a "+output_file+" "+intermediate_json, event="MemoryAnalysisLinux main")
            #os.remove(intermediate_json)
        else:
            logger.error(sample_hash=sample_fingerprint, message="Memory dump NOT present", event="MemoryAnalysisLinux main")
    except Exception as e:
        sys.exit("some error occurred" + str(e))
    sys.exit(None)

# logger.debug(sample_hash=sample_fingerprint, message="")
