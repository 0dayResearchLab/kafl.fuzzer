# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Launch Qemu VMs and execute test inputs produced by kAFL-Fuzzer.
"""

import ctypes
import mmap
import os
import socket
import struct
import subprocess
import sys
import time

from kafl_fuzzer.common.logger import logger
from kafl_fuzzer.common.util import read_binary_file, atomic_write, strdump, print_hprintf
from kafl_fuzzer.technique.redqueen.workdir import RedqueenWorkdir
from kafl_fuzzer.worker.execution_result import ExecutionResult
from kafl_fuzzer.worker.qemu_aux_buffer import QemuAuxBuffer
from kafl_fuzzer.worker.qemu_aux_buffer import QemuAuxRC as RC

class QemuIOException(Exception):
        """Exception raised when Qemu interaction fails"""
        pass

class qemu:

    def __init__(self, pid, config, debug_mode=False, notifiers=True, resume=False):

        self.debug_mode = debug_mode
        self.ijonmap_size = 0x1000 # quick fix - bitmaps are not processed!
        self.bitmap_size = config.bitmap_size
        self.payload_size = config.payload_shm_size
        self.payload_limit = config.payload_shm_size - 5
        self.config = config
        self.pid = pid
        self.alt_bitmap = bytearray(self.bitmap_size)
        self.alt_edges = 0
        self.bb_seen = 0

        self.process = None
        self.control = None
        self.persistent_runs = 0

        work_dir = self.config.work_dir
        project_name = work_dir.split("/")[-1]

        self.qemu_aux_buffer_filename = work_dir + "/aux_buffer_%d" % self.pid

        self.bitmap_filename = work_dir + "/bitmap_%d" % self.pid
        self.ijonmap_filename = work_dir + "/ijon_%d" % self.pid
        self.payload_filename = work_dir + "/payload_%d" % self.pid
        self.control_filename = work_dir + "/interface_%d" % self.pid
        self.qemu_trace_log = work_dir + "/qemu_trace_%02d.log" % self.pid
        self.serial_logfile = work_dir + "/serial_%02d.log" % self.pid
        self.hprintf_log = self.config.log_hprintf or self.config.log_crashes
        self.hprintf_logfile = work_dir + "/hprintf_%02d.log" % self.pid

        self.redqueen_workdir = RedqueenWorkdir(self.pid, config)
        self.redqueen_workdir.init_dir()

        self.starved = False
        self.exiting = False

        self.cmd = self.config.qemu_path

        # TODO: list append should work better than string concatenation, especially for str.replace() and later popen()
        self.cmd += " -enable-kvm" \
                    " -serial file:" + self.serial_logfile + \
                    " -m " + str(config.mem) + \
                    " -net none" \
                    " -chardev socket,server,nowait,path=" + self.control_filename + \
                    ",id=nyx_socket" \
                    " -device nyx,chardev=nyx_socket" + \
                    ",workdir=" + work_dir + \
                    ",worker_id=%d" % self.pid + \
                    ",bitmap_size=" + str(self.bitmap_size) + \
                    ",input_buffer_size=" + str(self.payload_size)

        if self.config.trace:
            self.cmd += ",dump_pt_trace"

        if self.config.trace_cb:
            self.cmd += ",edge_cb_trace"

        if self.config.sharedir:
            self.cmd += ",sharedir=" + self.config.sharedir

        if not notifiers:
            self.cmd += ",crash_notifier=False"

        # qemu snapshots only work in VM mode (disk+ram image)
        #if self.config.kernel or self.config.bios:
        #    self.cmd += ",disable_snapshot=True"

        for i in range(4):
            key = "ip" + str(i)
            if getattr(config, key, None):
                range_a = hex(getattr(config, key)[0]).replace("L", "")
                range_b = hex(getattr(config, key)[1]).replace("L", "")
                self.cmd += ",ip" + str(i) + "_a=" + range_a + ",ip" + str(i) + "_b=" + range_b

        if self.debug_mode:
            #self.cmd += " -d kafl -D " + self.qemu_trace_log
            pass

        self.cmd += " -no-reboot"

        if self.config.gdbserver:
            #self.cmd += " -trace events=/tmp/events"
            self.cmd += " -s -S"

        if self.config.X:
            if pid == 0 or pid == 1337:
                self.cmd += " -display %s" % self.config.X
        else:
            self.cmd += " -display none"

        if self.config.extra:
            self.cmd += " " + self.config.extra

        # Lauch either as VM snapshot, direct kernel/initrd boot, or -bios boot
        if self.config.vm_image:
            self.cmd += " -drive file=" + self.config.vm_image
        elif self.config.kernel:
            self.cmd += " -kernel " + self.config.kernel
            if self.config.initrd:
                self.cmd += " -initrd " + self.config.initrd + " -append BOOTPARAM "
        elif self.config.bios:
            self.cmd += " -bios " + self.config.bios
        else:
            assert(False), "Must supply either -bios or -kernel or -vm_image option"

        #self.cmd += " -machine q35 " ## cannot do fast_snapshot
        self.cmd += " -machine kAFL64-v1"
        self.cmd += " -cpu kAFL64-Hypervisor-v1,+vmx"
        #self.cmd += " -cpu kvm64-v1" #,+vmx

        if pid == 0 or pid == 1337 and not resume:
            if self.config.vm_snapshot:
                self.cmd += " -fast_vm_reload path=%s,load=off,pre_path=%s " % (
                        work_dir + "/snapshot/",
                        self.config.vm_snapshot)
            else:
                self.cmd += " -fast_vm_reload path=%s,load=off " % (
                        work_dir + "/snapshot/")
        else:
            # TDX: all VMs perform regular boot & race for snapshot lock
            self.cmd += " -fast_vm_reload path=%s,load=off " % (
                         work_dir + "/snapshot/")

        # split cmd into list of arguments for Popen(), replace BOOTPARAM as single element
        self.cmd = [_f for _f in self.cmd.split(" ") if _f]
        c = 0
        for i in self.cmd:
            if i == "BOOTPARAM":
                self.cmd[c] = "nokaslr oops=panic nopti mitigations=off console=ttyS0"
                break
            c += 1

        # delayed Qemu startup - launching too many at once seems to cause random crashes
        if pid != 1337:
            time.sleep(0.1*pid)

    def __str__(self):
        return "Worker-%02d" % self.pid

    # Asynchronous exit by Worker. Note this may be called multiple times
    # while we were in the middle of shutdown(), start(), send_payload(), ..
    def async_exit(self):
        if self.exiting:
            sys.exit(0)

        self.exiting = True
        self.shutdown()


    def shutdown(self):
        logger.info("%s Shutting down Qemu after %d execs.." % (self, self.persistent_runs))

        if not self.process:
            # start() has never been called, all files/shm are closed.
            return 0

        # If Qemu exists, try to graciously read its I/O and SIGTERM it.
        # If still alive, attempt SIGKILL or loop-wait on kill -9.
        output = ""
        try:
            self.process.terminate()
            output = strdump(self.process.communicate(timeout=1)[0], verbatim=True)
        except:
            pass

        if self.process.returncode is None:
            try:
                self.process.kill()
            except:
                pass

        logger.file_log("INFO", "%s exit code: %s" % (self, str(self.process.returncode)))

        if len(output) > 0:
            header = "\n=================<%s Console Output>==================\n" %self
            footer = "====================</Console Output>======================\n"
            logger.file_log("INFO", header + output + footer)

        # on full debug, also include the serial log at point of Qemu exit
        serial_out = strdump(read_binary_file(self.serial_logfile), verbatim=True)
        if len(serial_out) > 0:
            header = "\n=================<%s Serial Output>==================\n" % self
            footer = "====================</Serial Output>======================\n"
            logger.file_log("INFO", header + serial_out + footer)

        try:
            # TODO: exec_res keeps from_buffer() reference to kafl_shm
            self.kafl_shm.close()
        except BufferError as e:
            pass

        try:
            self.fs_shm.close()
        except:
            pass

        try:
            os.close(self.kafl_shm_f)
        except:
            pass

        try:
            os.close(self.fs_shm_f)
        except:
            pass

        for tmp_file in [
                self.qemu_aux_buffer_filename,
                self.payload_filename,
                self.control_filename,
                self.ijonmap_filename,
                self.bitmap_filename]:
            try:
                os.remove(tmp_file)
            except:
                pass

        self.redqueen_workdir.rmtree()
        return self.process.returncode

    def start(self):

        if self.exiting:
            return False

        self.persistent_runs = 0

        if self.pid == 0 or self.pid == 1337: ## 1337 is debug instance!
            logger.info(("%s Launching virtual machine...CMD:\n" % self) + ' '.join(self.cmd))
        else:
            logger.info("%s Launching virtual machine..." % self)


        # Launch Qemu. stderr to stdout, stdout is logged on VM exit
        # os.setpgrp() prevents signals from being propagated to Qemu, instead allowing an
        # organized shutdown via async_exit()
        self.process = subprocess.Popen(self.cmd,
                preexec_fn=os.setpgrp,
                stdin=subprocess.DEVNULL)
                # TODO: shutdown() fails to capture libxdc fprintf() - why?
                #stdin=subprocess.PIPE,
                #stdout=subprocess.PIPE,
                #stderr=subprocess.STDOUT)
                #stdin=subprocess.DEVNULL,
                #stdout=subprocess.DEVNULL,
                #stderr=subprocess.DEVNULL)

        try:
            self.__qemu_connect()
            self.__qemu_handshake()
        except (OSError, BrokenPipeError) as e:
            if not self.exiting:
                logger.error("%s Failed to launch Qemu: %s" % (self, str(e)))
                self.shutdown()
            return False

        return True

    # release Qemu and wait for it to return
    def run_qemu(self):
        self.control.send(b'x')
        self.control.recv(1)

    def __qemu_handshake(self):

        self.run_qemu()

        self.qemu_aux_buffer = QemuAuxBuffer(self.qemu_aux_buffer_filename)
        if not self.qemu_aux_buffer.validate_header():
            logger.error("%s Invalid header in qemu_aux_buffer.py. Abort." % self)
            self.async_exit()

        while self.qemu_aux_buffer.get_state() != 3:
            logger.debug("%s Waiting for target to enter fuzz mode.." % self)
            self.run_qemu()
            result = self.qemu_aux_buffer.get_result()
            if result.exec_code == RC.ABORT:
                self.handle_habort()
            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()

        logger.debug("%s Handshake done." % self)

        if not self.config.no_fast_reload:
            self.qemu_aux_buffer.set_reload_mode(True)
        self.qemu_aux_buffer.set_timeout(self.config.timeout_hard)

        return

    def __qemu_connect(self):
        # Note: setblocking() disables the timeout! settimeout() will automatically set blocking!
        self.control = socket.socket(socket.AF_UNIX)
        self.control.settimeout(None)
        self.control.setblocking(1)

        # TODO: Don't try forever, set some timeout..
        while True:
            try:
                self.control.connect(self.control_filename)
                break
            except socket.error:
                if self.process.returncode is not None:
                    raise
            logger.debug("Waiting for Qemu connect..")


        self.ijon_shm_f     = os.open(self.ijonmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.kafl_shm_f     = os.open(self.bitmap_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)
        self.fs_shm_f       = os.open(self.payload_filename, os.O_RDWR | os.O_SYNC | os.O_CREAT)

        os.ftruncate(self.ijon_shm_f, self.ijonmap_size)
        os.ftruncate(self.kafl_shm_f, self.bitmap_size)
        os.ftruncate(self.fs_shm_f, self.payload_size)

        self.kafl_shm = mmap.mmap(self.kafl_shm_f, 0)
        self.c_bitmap = (ctypes.c_uint8 * self.bitmap_size).from_buffer(self.kafl_shm)
        self.fs_shm = mmap.mmap(self.fs_shm_f, 0)

        return True

    def handle_hprintf(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')

        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)
        elif not self.config.quiet:
            print_hprintf(msg)

    def handle_habort(self):
        msg = self.qemu_aux_buffer.get_misc_buf()
        msg = msg.decode('latin-1', errors='backslashreplace')
        msg = "Guest ABORT: %s" % msg

        logger.error(msg)
        if self.hprintf_log:
            with open(self.hprintf_logfile, "a") as f:
                f.write(msg)

        self.run_qemu()
        raise QemuIOException(msg)

    # Fully stop/start Qemu instance to store logs + possibly recover
    def restart(self):
        # Nyx backend does not tend to die anymore so this is a NOP
        # To enable recovery again, new Qemu instances must respect the snapshot
        # settings and avoid overwriting a possibly existing snapshot
        return True

    # Reset Qemu after crash/timeout - not required anymore
    def reload(self):
        return True

    # Wait forever on Qemu to execute the payload - useful for interactive debug
    def debug_payload(self):

        self.set_timeout(0)
        #self.send_payload()
        while True:
            self.run_qemu()
            result = self.qemu_aux_buffer.get_result()
            if result.page_fault:
                logger.warn("Page fault encountered!")
            if result.pt_overflow:
                logger.warn("PT trashed!")
            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
                continue
            if result.exec_code == RC.ABORT:
                self.handle_habort()

        logger.info("Result: %s\n" % self.exit_reason(result))
        #self.audit(result)
        return result

    def send_payload(self):

        if self.exiting:
            sys.exit(0)

        result = None
        old_address = 0
        self.persistent_runs += 1
        start_time = time.time()

        while True:
            self.run_qemu()

            result = self.qemu_aux_buffer.get_result()

            if result.pt_overflow:
                logger.warn("PT trashed!")

            if result.exec_code == RC.HPRINTF:
                self.handle_hprintf()
                continue

            if result.exec_code == RC.ABORT:
                self.handle_habort()

            if result.exec_done:
                break

            if result.page_fault:
                if result.page_fault_addr == old_address:
                    logger.error("%s Failed to resolve page after second execution! Qemu status:\n%s" % (self, str(result._asdict())))
                    break
                old_address = result.page_fault_addr
                self.qemu_aux_buffer.dump_page(result.page_fault_addr)

        # record highest seen BBs
        self.bb_seen = max(self.bb_seen, result.bb_cov)

        #runtime = result.runtime_sec + result.runtime_usec/1000/1000
        res = ExecutionResult(
                self.c_bitmap, self.bitmap_size,
                self.exit_reason(result), time.time() - start_time)

        if result.exec_code == RC.STARVED:
            res.starved = True

        #self.audit(res.copy_to_array())
        #self.audit(bytearray(self.c_bitmap))

        return res

    def audit(self, bitmap):

        if len(bitmap) != self.bitmap_size:
            logger.info("bitmap size: %d" % len(bitmap))

        new_bytes = 0
        new_bits = 0
        for idx in range(self.bitmap_size):
            if bitmap[idx] != 0x00:
                if self.alt_bitmap[idx] == 0x00:
                    self.alt_bitmap[idx] = bitmap[idx]
                    new_bytes += 1
                else:
                    new_bits += 1
        if new_bytes > 0:
            self.alt_edges += new_bytes;
            logger.info("%s New bytes: %03d, bits: %03d, total edges seen: %03d" % (
                self, new_bytes, new_bits, self.alt_edges))


    def exit_reason(self, result):
        if result.exec_code == RC.CRASH:
            return "crash"
        if result.exec_code == RC.TIMEOUT:
            return "timeout"
        elif result.exec_code == RC.SANITIZER:
            return "kasan"
        elif result.exec_code == RC.SUCCESS:
            return "regular"
        elif result.exec_code == RC.STARVED:
            return "regular"
        else:
            raise QemuIOException("Unknown QemuAuxRC code")

    def set_timeout(self, timeout):
        assert(self.qemu_aux_buffer)
        self.qemu_aux_buffer.set_timeout(timeout)

    def get_timeout(self):
        return self.qemu_aux_buffer.get_timeout()

    def set_trace_mode(self, enable):
        assert(self.qemu_aux_buffer)
        self.qemu_aux_buffer.set_trace_mode(enable)


    def set_payload(self, payload):
        # Ensure the payload fits into SHM. Caller has to cut off since they also report findings.
        # actual payload is limited to payload_size - sizeof(uint32) - sizeof(uint8)
        assert(len(payload) <= self.payload_limit), "Payload size %d > SHM limit %d. Check size/shm config" % (len(payload),self.payload_limit)

        #if len(payload) > self.payload_limit:
        #    payload = payload[:self.payload_limit]
        try:
            struct.pack_into("=I", self.fs_shm, 0, len(payload))
            self.fs_shm.seek(4)
            self.fs_shm.write(payload)
            #self.fs_shm.flush()
        except ValueError:
            if self.exiting:
                sys.exit(0)
            # Qemu crashed. Could be due to prior payload but more likely harness/config is broken..
            logger.error("%s Failed to set new payload - Qemu crash?" % self)
            raise
