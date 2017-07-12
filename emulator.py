# -*- coding: utf-8 -*-
# Andre <sh4ka> Moulu / ge0n0sis.github.io
#
# Tiny and basic emulator of a small part of the dalvik instruction set
#
# Please keep in mind this is only a PoC ...
#

import logging
from IntCast import *

logging.basicConfig(
    filename='emulator.log',
    filemode="w",
    format='[%(asctime)-15s] [%(levelname)s] => %(message)s',
    level=logging.INFO)
logger = logging.getLogger("Emulator")

class TinySmaliEmulator():
    registers = {}
    smali = {}
    smaliInfos = {}
    breakpoints = {}
    currentInstruction = None
    mustSupportAllInstructions = False
    stop = False
    result = None

    def __init__(self, plugin):
        self.plugin = plugin
        self.jeb = self.plugin.jeb
        self.dex = self.jeb.getDex()
        self.breakpoints = {
            "before": {},
            "after": {},
            "offset": {}
        }


    def addBreakpoint(self, bpType, value, callback):
        """
        Add a breakpoint.
        - bpType: before/after/offset
        - value: the address or instruction name.
        - callback: the function to be called on breakpoint hit.
        """
        assert bpType in self.breakpoints.keys(), "invalid breakpoint type: %s" % (bpType)
        self.breakpoints[bpType][value] = callback

    def deleteBreakpoint(self, bpType, value):
        assert bpType in self.breakpoints.keys(), "invalid breakpoint type: %s" % (bpType)
        del self.breakpoints[bpType][value]

    # should we trigger a breakpoint ?
    def handleBreakpoint(self, bpType, value):
        assert bpType in self.breakpoints.keys(), "invalid breakpoint type: %s" % (bpType)
        if value in self.breakpoints[bpType]:
            self.breakpoints[bpType][value](self)

    def initialize(self, className, methodName):
        self.disas(className, methodName)

    def run(self, parameters):
        """
        parameters is a list of param value for the function to be called
        """
        self.runEngine(parameters)
        logger.info("End of the execution. registers:")
        logger.info(self.registers)

    def cleanState(self, cleanBreakpoint=False):
        self.registers = {}
        self.stop = False
        self.result = None
        self.currentInstruction = None
        if cleanBreakpoint:
            self.breakpoints = {}

    def getResult(self):
        return self.result

    def getParametersValues(self, ins, n):
        """
        Read up to the n first parameters of the specified instruction
        """
        out = []
        params = ins.getParameters()
        for i in range(n):
            out.append(params[i].getValue())

        if len(out) == 1:
            return out[0]
        else:
            return out

    def getRegister(self, n):
        return self.registers["v%d" % (n)]

    def setRegister(self, n, value):
        self.registers["v%d" % (n)] = value

    def getSpecialRegister(self, n):
        return self.registers[n]

    def setSpecialRegister(self, n, value):
        self.registers[n] = value

    def _getInstructionName(self, ins):
        return ins.getMnemonic()

    def _getInstructionSize(self, ins):
        return ins.getSize()

    def _getStringFromIndex(self, ins, index):
        return self.dex.getString(index)

    def calculateNextPC(self, ins):
        """
          I wanna be PC!
          (Woo Woo)

          It's just the way to be for me... And you!
          (Woo Woo)

          [...]

          (I call woo woo on you!) (Woo Woo)
        """
        currentPC = self.getSpecialRegister("pc")
        self.setSpecialRegister("pc", currentPC + self._getInstructionSize(ins))

    def diffRegisters(self, before, after):
        """
        This fonction will log the modified registers values after the execution of an instruction
        """
        diff = {}
        for key in before.keys():
            if before[key] != after[key]:
                diff[key] = after[key]
        for key in after.keys():
            if not before.has_key(key):
                diff[key] = after[key]

        keys = diff.keys()
        keys.sort()
        for k in keys:
            logger.debug("%s = %s" % (k, str(self.registers[k])))

    def disas(self, className, methodName):
        """
        Retrieve information about the specified method like the number of arguments or "allocated" registers.
        Disassemble all the instructions and check if implementation is needed or not for them.
        """
        cl = self.dex.getClass(className)
        m = self.dex.getMethodData(className + "->" + methodName)

        mCodeItem = m.getCodeItem()

        self.smaliInfos["registerCount"] = mCodeItem.getRegisterCount()
        self.smaliInfos["argumentCount"] = mCodeItem.getInputArgumentCount()

        logger.info("Disassembling %s->%s" % (className, methodName))
        logger.info(self.smaliInfos)

        for ins in mCodeItem.getInstructions():
            self.smali[ins.getOffset()] = ins

            logger.debug("[%d (+%d)] %s %s" % (ins.getOffset(), ins.getSize(), ins.getMnemonic(), ",".join(
                map(lambda x: "[%d,%d]" % (x.getType(), x.getValue()), ins.getParameters()))))

            if ins.getMnemonic() == "packed-switch":
                switchTable = {}
                for sd in ins.getSwitchData().getElements():
                    switchTable[sd.getKey()] = sd.getTarget()
                self.smaliInfos["switchTable_%d" % ins.getParameters()[1].getValue()] = switchTable

        self.checkForInstructionsSupport()

    def _mangleInstructionName(self, name):
        return "_ins_" + name.replace("/", "_").replace("-", "_")

    def _mangleMethodName(self, class_name, method_name):
        # HACK!!1§! redo this with a proper way
        class_name = class_name[1:-1].replace("/", "_")
        method_name = method_name.replace("(", "_").replace(")", "_").replace("[", "_").replace(";", "_").replace("<", "_").replace(">", "_").replace("/", "_")
        return "_class_" + class_name + "__" + method_name

    def checkForInstructionsSupport(self):
        listOfInstructions = set(map(lambda x: self._getInstructionName(x), self.smali.values()))
        notSupportedInstructions = []
        for i in listOfInstructions:
            internalInsName = self._mangleInstructionName(i)
            if internalInsName not in dir(self) or callable(getattr(self, internalInsName)) is not True:
                notSupportedInstructions.append(i)

        if len(notSupportedInstructions) and self.mustSupportAllInstructions:
            raise Exception(
                "If you want to emulate this function, you will have to support these instructions: %s" % notSupportedInstructions)

    def runEngine(self, parameters):
        """
        Emulate the initialized method with the specified parameters.
        At the end of the emulation, the result should be in self.result.
        """
        # Translate parameters into registers value ...
        assert len(parameters) == self.smaliInfos["argumentCount"]
        for i in range(len(parameters)):
            r = self.smaliInfos["registerCount"] - self.smaliInfos["argumentCount"] + i
            self.setRegister(r, parameters[i])

        # and start the big loop :)
        self.setSpecialRegister("pc", 0)
        self.setSpecialRegister("result", None)
        self.setSpecialRegister("result-object", None)

        while True:
            self.handleBreakpoint("offset", self.getSpecialRegister("pc"))

            self.currentInstruction = self.smali[self.getSpecialRegister("pc")]
            self.handleBreakpoint("before", self._getInstructionName(self.currentInstruction))

            if self.stop:
                break

            self.emulateInstruction(self.currentInstruction)
            self.handleBreakpoint("after", self._getInstructionName(self.currentInstruction))

        print "end of execution"

    def emulateInstruction(self, ins):
        insName = self._getInstructionName(ins)
        usedRegisters = map(lambda x: x.getValue(), filter(lambda x: x.getType() == 0, ins.getParameters()))

        logger.debug("Trying to emulate instruction %s" % (insName))
        logger.debug("[%d] %s %s" % (ins.getOffset(), ins.getMnemonic(), ",".join(
            map(lambda x: "[%d,%d]" % (x.getType(), x.getValue()), ins.getParameters()))))

        logger.debug("=" * 40 + " BEFORE " + "=" * 40)
        for i in usedRegisters:
            if self.registers.has_key("v%d" % i):
                logger.debug("v%d = %s" % (i, str(self.getRegister(i))))
            else:
                logger.debug("v%d = undefined" % (i))
        before = self.registers.copy()

        internalInsName = self._mangleInstructionName(insName)
        if internalInsName in dir(self) and callable(getattr(self, internalInsName)):
            getattr(self, internalInsName)(ins)
        else:
            raise Exception("instruction not handled yet %s" % (insName))

        logger.debug("=" * 40 + " AFTER " + "=" * 40)
        self.diffRegisters(before, self.registers)
        logger.debug("=" * 88)

    #
    # Subset of Smali instruction set
    # /!\ Only the subset needed to emulate encountered decryptString() routines is handled /!\
    #

    # opcode 00 10x nop
    def _ins_nop(self, ins):
        self.calculateNextPC(ins)

    # opcode 01 12x move vA, vB
    def _ins_move(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode 02 22x move/from16 vAA, vBBBB
    def _ins_move_from16(self, ins):
        self._ins_move(self, ins)

    # opcode 03 32x move/16 vAAAA, vBBBB
    def _ins_move_16(self, ins):
        self._ins_move(self, ins)

    # opcode 04 12x move-wide vA, vB
    def _ins_move_wide(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        v1, v2 = self.getRegister(src), self.getRegister(src + 1)  # needed to prevent overwriting
        self.setRegister(dst, v1)
        self.setRegister(dst + 1, v2)
        self.calculateNextPC(ins)

    # opcode 05 22x move-wide/from16 vAA, vBBBB
    def _ins_move_wide_from16(self, ins):
        self._ins_move_wide(ins)

    # opcode 06 32x move-wide/16 vAAAA, vBBBB
    def _ins_move_wide_16(self, ins):
        self._ins_move_wide(ins)

    # opcode 07 12x move-object vA, vB
    def _ins_move_object(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode 08 22x move-object/from16 vAA, vBBBB
    def _ins_move_object_from16(self, ins):
        self._ins_move_object(ins)

    # opcode 09 32x move-object/16 vAAAA, vBBBB
    def _ins_move_object_16(self, ins):
        self._ins_move_object(ins)

    # opcode 0a 11x move-result vAA
    def _ins_move_result(self, ins):
        self.setRegister(self.getParametersValues(ins, 1), self.getSpecialRegister("result"))
        self.calculateNextPC(ins)

    # opcode 0b 11x move-result-wide vAA
    def _ins_move_result_wide(self, ins):
        v1, v2 = self.getSpecialRegister("result")
        self.setRegister(self.getParametersValues(ins, 1), v1)
        self.setRegister(self.getParametersValues(ins, 1) + 1, v2)
        self.calculateNextPC(ins)

    # opcode 0c 11x move-result-object vAA
    def _ins_move_result_object(self, ins):
        self.setRegister(self.getParametersValues(ins, 1), self.getSpecialRegister("result-object"))
        self.calculateNextPC(ins)

    # opcode 0d 11x move-exception vAA
    def _ins_move_exception(self, ins):
        raise Exception("exception related instructions not handled yet")

    # opcode 0e 10x return-void
    def _ins_return_void(self, ins):
        logger.debug("return void")
        self.stop = True

    # opcode 0f 11x return vAA
    def _ins_return(self, ins):
        r = self.getParametersValues(ins, 1)
        self.result = self.getRegister(r)
        logger.debug("return")
        self.stop = True

    # opcode 10 11x return-wide vAA
    def _ins_return_wide(self, ins):
        r = self.getParametersValues(ins, 1)
        self.result = [self.getRegister(r), self.getRegister(r + 1)]
        logger.debug("return-wide")
        self.stop = True

    # opcode 11 11x return-object vAA
    def _ins_return_object(self, ins):
        o = self.getParametersValues(ins, 1)
        self.result = self.getRegister(o)
        logger.info("return object: %s" % self.result)
        self.stop = True

    # opcode 12 11n const/4 vA, #+B
    def _ins_const_4(self, ins):
        self._ins_const(ins)

    # opcode 13 21s const/16 vAA, #+BBBB
    def _ins_const_16(self, ins):
        self._ins_const(ins)

    # opcode 14 31i const vAA, #+BBBBBBBB
    def _ins_const(self, ins):
        r, v = self.getParametersValues(ins, 2)
        self.setRegister(r, v)
        self.calculateNextPC(ins)

    # opcode 15 21h const/high16 vAA, #+BBBB0000
    def _ins_const_high16(self, ins):
        r, v = self.getParametersValues(ins, 2)
        self.setRegister(r, v)
        self.calculateNextPC(ins)

    # opcode 16 21s const-wide/16 vAA, #+BBBB
    def _ins_const_wide_16(self, ins):
        self._ins_const_wide(ins)

    # opcode 17 31i const-wide/32 vAA, #+BBBBBBBB
    def _ins_const_wide_32(self, ins):
        self._ins_const_wide(ins)

    # opcode 18 51l const-wide vAA, #+BBBBBBBBBBBBBBBB
    def _ins_const_wide(self, ins):
        r, v = self.getParametersValues(ins, 2)
        v1 = v >> 32 & 0xFFFFFFFF
        v2 = v & 0xFFFFFFFF
        self.setRegister(r, v1)
        self.setRegister(r + 1, v2)
        self.calculateNextPC(ins)

    # opcode 19 21h const-wide/high16 vAA, #+BBBB000000000000
    def _ins_const_wide_high16(self, ins):
        self._ins_const_wide(ins)

    # opcode 1a 21c const-string vAA, string@BBBB
    def _ins_const_string(self, ins):
        dst, index = self.getParametersValues(ins, 2)
        self.setRegister(dst, self._getStringFromIndex(ins, index))
        self.calculateNextPC(ins)

    # opcode 1b 31c const-string/jumbo vAA, string@BBBBBBBB
    def _ins_const_string_jumbo(self, ins):
        self._ins_const_string(ins)

    # opcode 1c 21c const-class vAA, type@BBBB
    def _ins_const_class(self, ins):
        raise Exception("not implemented yet")

    # opcode 1d 11x monitor-enter vAA
    def _ins_monitor_enter(self, ins):
        raise Exception("not implemented yet")

    # opcode 1e 11x monitor-leave vAA
    def _ins_monitor_leave(self, ins):
        raise Exception("not implemented yet")

    # opcode 1f 21c check-cast vAA, type@BBBB
    def _ins_check_cast(self, ins):
        raise Exception("not implemented yet")

    # opcode 20 22c instance-of vA, vB, type@CCCC
    def _ins_instance_of(self, ins):
        raise Exception("not implemented yet")

    # opcode 21 21 12x array-length vA, vB
    def _ins_array_length(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, len(self.getRegister(src)))
        self.calculateNextPC(ins)

    # opcode 22 21c new-instance vAA, type@BBBB
    def _ins_new_instance(self, ins):
        dst, dexType = self.getParametersValues(ins, 2)
        self.setRegister(dst, "new instance of %s" % (self.dex.getType(dexType)))
        self.calculateNextPC(ins)

    # opcode 23 22c new-array vA, vB, type@CCCC
    def _ins_new_array(self, ins):
        dst, size, t = self.getParametersValues(ins, 3)
        self.setRegister(dst, [-1] * self.getRegister(size))
        self.calculateNextPC(ins)

    # opcode 24 35c filled-new-array {vC, vD, vE, vF, vG}, type@BBBB
    def _ins_filled_new_array(self, ins):
        raise Exception("not implemented yet")

    # opcode 25 3rc filled-new-array/range {vCCCC .. vNNNN}, type@BBBB
    def _ins_filled_new_array_range(self, ins):
        raise Exception("not implemented yet")

    # opcode 26 31t fill-array-data vAA, +BBBBBBBB
    def _ins_fill_array_data(self, ins):
        raise Exception("not implemented yet")

    # opcode 27 11x throw vAA
    def _ins_throw(self, ins):
        raise Exception("not implemented yet")

    # opcode 28 10t goto +AA
    def _ins_goto(self, ins):
        offset = self.getParametersValues(ins, 1)
        self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (2 * offset))

    # opcode 29 20t goto/16 +AAAA
    def _ins_goto_16(self, ins):
        self._ins_goto(ins)

    # opcode 2a 30t goto/32 +AAAAAAAA
    def _ins_goto_32(self, ins):
        self._ins_goto(ins)

    # opcode 2b 31t packed-switch vAA, +BBBBBBBB
    def _ins_packed_switch(self, ins):
        src, switchTable = self.getParametersValues(ins, 2)
        switchTable = self.smaliInfos["switchTable_%d" % switchTable]
        src = self.getRegister(src)
        if src in switchTable.keys():
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (switchTable[src] * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 2c 31t sparse-switch vAA, +BBBBBBBB
    def _ins_sparse_switch(self, ins):
        raise Exception("not implemented yet")

    def _ins_packed_switch_payload(self, ins):
        self.calculateNextPC(ins)

    def _ins_sparse_switch_payload(self, ins):
        self.calculateNextPC(ins)

    # opcode 2d 23x cmpl-float vAA, vBB, vCC (lt bias)
    # opcode 2e 23x cmpg-float vAA, vBB, vCC (gt bias)
    # opcode 2f 23x cmpl-double vAA, vBB, vCC (lt bias)
    # opcode 30 23x cmpg-double vAA, vBB, vCC (gt bias)
    # opcode 31 23x cmp-long vAA, vBB, vCC

    # opcode 32 22t if-eq vA, vB, +CCCC
    def _ins_if_eq(self, ins):
        a1, a2, offset = self.getParametersValues(ins, 3)
        if self.getRegister(a1) == self.getRegister(a2):
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 33 22t if-ne vA, vB, +CCCC
    def _ins_if_ne(self, ins):
        a1, a2, offset = self.getParametersValues(ins, 3)
        if self.getRegister(a1) != self.getRegister(a2):
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 34 22t if-lt vA, vB, +CCCC
    def _ins_if_lt(self, ins):
        a1, a2, offset = self.getParametersValues(ins, 3)
        if self.getRegister(a1) < self.getRegister(a2):
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 35 22t if-ge vA, vB, +CCCC
    def _ins_if_ge(self, ins):
        a1, a2, offset = self.getParametersValues(ins, 3)
        if self.getRegister(a1) >= self.getRegister(a2):
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 36 22t if-gt vA, vB, +CCCC
    def _ins_if_gt(self, ins):
        a1, a2, offset = self.getParametersValues(ins, 3)
        if self.getRegister(a1) > self.getRegister(a2):
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 37 22t if-le vA, vB, +CCCC
    def _ins_if_le(self, ins):
        a1, a2, offset = self.getParametersValues(ins, 3)
        if self.getRegister(a1) <= self.getRegister(a2):
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 38 21t if-eqz vAA, +BBBB
    def _ins_if_eqz(self, ins):
        a1, offset = self.getParametersValues(ins, 2)
        if self.getRegister(a1) == 0:
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 39 21t if-nez vAA, +BBBB
    def _ins_if_nez(self, ins):
        src, offset = self.getParametersValues(ins, 2)
        if self.getRegister(src) is None or self.getRegister(src) != 0:
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 3a 21t if-ltz vAA, +BBBB
    def _ins_if_ltz(self, ins):
        src, offset = self.getParametersValues(ins, 2)
        if self.getRegister(src) < 0:
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 3b 21t if-gez vAA, +BBBB
    def _ins_if_gez(self, ins):
        src, offset = self.getParametersValues(ins, 2)
        if self.getRegister(src) >= 0:
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 3c 21t if-gtz vAA, +BBBB
    def _ins_if_gtz(self, ins):
        src, offset = self.getParametersValues(ins, 2)
        if self.getRegister(src) > 0:
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 3d 21t if-lez vAA, +BBBB
    def _ins_if_lez(self, ins):
        src, offset = self.getParametersValues(ins, 2)
        if self.getRegister(src) <= 0:
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (offset * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 3e..43 10x (unused)

    # opcode 44 23x aget vAA, vBB, vCC
    def _ins_aget(self, ins):
        dst, src, offset = self.getParametersValues(ins, 3)
        offset = self.getRegister(offset)
        if type(self.getRegister(src)) != type([]) or offset < 0 or offset >= len(self.getRegister(src)):
            raise Exception("Emulation runtime crash at _ins_aget")

        self.setRegister(dst, self.getRegister(src)[offset])
        self.calculateNextPC(ins)

    # opcode 45 23x aget-wide vAA, vBB, vCC
    def _ins_aget_wide(self, ins):
        dst, src, offset = self.getParametersValues(ins, 3)
        offset = self.getRegister(offset)
        if type(self.getRegister(src)) != type([]) or offset < 0 or offset >= len(self.getRegister(src)):
            raise Exception("Emulation runtime crash at _ins_aget_wide")

        v = self.getRegister(src)[offset]
        v1 = v >> 32 & 0xFFFFFFFF
        v2 = v & 0xFFFFFFFF
        self.setRegister(dst, v1)
        self.setRegister(dst + 1, v2)
        self.calculateNextPC(ins)

    # opcode 46 23x aget-object vAA, vBB, vCC
    def _ins_aget_object(self, ins):
        self._ins_aget(ins)

    # opcode 47 23x aget-boolean vAA, vBB, vCC
    def _ins_aget_boolean(self, ins):
        self._ins_aget(ins)

    # opcode 48 23x aget-byte vAA, vBB, vCC
    def _ins_aget_byte(self, ins):
        self._ins_aget(ins)

    # opcode 49 23x aget-char vAA, vBB, vCC
    def _ins_aget_char(self, ins):
        self._ins_aget(ins)

    # opcode 4a 23x aget-short vAA, vBB, vCC
    def _ins_aget_short(self, ins):
        self._ins_aget(ins)

    # opcode 4d 23x aput-object vAA, vBB, vCC
    def _ins_aput_object(self, ins):
        src, dst, offset = self.getParametersValues(ins, 3)
        offset = self.getRegister(offset)
        if type(self.getRegister(dst)) != type([]) or offset < 0 or offset >= len(self.getRegister(dst)):
            raise Exception("Emulation runtime crash at _ins_aput_object")

        tmp = self.getRegister(dst)
        tmp[offset] = self.getRegister(src)
        self.setRegister(dst, tmp)
        self.calculateNextPC(ins)

    # opcode 4f 23x aput-byte vAA, vBB, vCC
    def _ins_aput_byte(self, ins):
        src, dst, offset = self.getParametersValues(ins, 3)
        offset = self.getRegister(offset)
        if isinstance(self.getRegister(dst), unicode):
            self.setRegister(dst, list(self.getRegister(dst)))

        if type(self.getRegister(dst)) != type([]) or offset < 0 or offset >= len(self.getRegister(dst)):
            raise Exception("Emulation runtime crash at _ins_aput_byte")

        tmp = self.getRegister(dst)
        tmp[offset] = self.getRegister(src) % 256
        self.setRegister(dst, tmp)
        self.calculateNextPC(ins)

    # opcode 50 23x aput-char vAA, vBB, vCC
    def _ins_aput_char(self, ins):
        self._ins_aput_byte(ins)

    # opcode 51 23x aput-short vAA, vBB, vCC
    def _ins_aput_short(self, ins):
        src, dst, offset = self.getParametersValues(ins, 3)
        offset = self.getRegister(offset)
        if isinstance(self.getRegister(dst), unicode):
            self.setRegister(dst, list(self.getRegister(dst)))

        if type(self.getRegister(dst)) != type([]) or offset < 0 or offset >= len(self.getRegister(dst)):
            raise Exception("Emulation runtime crash at _ins_put_short")

        tmp = self.getRegister(dst)
        tmp[offset] = cast_to_short(self.getRegister(src))
        self.setRegister(dst, tmp)
        self.calculateNextPC(ins)

    # opcode 44..51 23x a lot of aput-kind/aget-kind not implemented
    # opcode 52..5f 22c  iinstanceop vA, vB, field@CCCC not implemented
    # opcode 60..6d 21c sstaticop vAA, field@BBBB not implemented

    # opcode 6e 35c invoke-virtual {vC, vD, vE, vF, vG}, meth@BBBB
    def _ins_invoke_virtual(self, ins):
        params = ins.getParameters()
        call = params[0].getValue()
        class_name, method_name = self.dex.getMethod(call).getSignature(0).split("->")
        internalMethodName = self._mangleMethodName(class_name, method_name)
        logger.info("trying to invoke %s %s as %s" % (class_name, method_name, internalMethodName))
        if internalMethodName in dir(self) and callable(getattr(self, internalMethodName)):
            getattr(self, internalMethodName)(params[1:])
        else:
            raise Exception("call not handled yet %s" % (internalMethodName))
        self.calculateNextPC(ins)

    # opcode 70 35c invoke-direct {vC, vD, vE, vF, vG}, meth@BBBB
    def _ins_invoke_direct(self, ins):
        self._ins_invoke_virtual(ins)

    # opcode 71 35c invoke-static {vC, vD, vE, vF, vG}, meth@BBBB
    def _ins_invoke_static(self, ins):
        self._ins_invoke_virtual(ins)

    # opcode 73 10x unused
    # opcode 74..78 3rc invoke-kind/range {vCCCC .. vNNNN}, meth@BBBB not implemented
    # opcode 79..7a 10x unused
    # opcode 7b..8f 12x unop vA, vB not implemented

    # opcode d8 22b add-int/lit8 vAA, vBB, #+CC
    def _ins_add_int_lit8(self, ins):
        self._ins_add_int_lit(ins)

    # opcode d0 22s add-int/lit16 vAA, vBB, #+CCCC
    def _ins_add_int_lit16(self, ins):
        self._ins_add_int_lit(ins)

    def _ins_add_int_lit(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) + v)
        self.calculateNextPC(ins)

    # opcode 90 23x add-int vAA, vBB, vCC
    def _ins_add_int(self, ins):
        dst, src, src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) + self.getRegister(src2))
        self.calculateNextPC(ins)

    # opcode b1 12x sub-int/2addr vA, vB
    def _ins_sub_int_2addr(self, ins):
        register, register2 = self.getParametersValues(ins, 2)
        self.setRegister(register, self.getRegister(register) - self.getRegister(register2))
        self.calculateNextPC(ins)

    # opcode 91 23x sub-int vAA, vBB, vCC
    def _ins_sub_int(self, ins):
        dst, src, src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) - self.getRegister(src2))
        self.calculateNextPC(ins)

    # opcode df 22b xor-int/lit8 vAA. vBB, #+CC
    def _ins_xor_int_lit8(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        src = self.getRegister(src)
        if isinstance(src, unicode) or isinstance(src, str):
            src = ord(src)

        self.setRegister(dst, src ^ v)
        self.calculateNextPC(ins)

    # opcode d7 22s xor-int/lit16 vA, vB, #+CCCC
    def _ins_xor_int_lit16(self, ins):
        self._ins_xor_int_lit8(ins)

    # opcode 97 23x xor-int vAA, vBB, vCC
    def _ins_xor_int(self, ins):
        dst, src1, src2 = self.getParametersValues(ins, 3)
        src1 = self.getRegister(src1)
        if isinstance(src1, unicode) or isinstance(src1, str):
            src1 = ord(src1)

        src2 = self.getRegister(src2)
        if isinstance(src2, unicode) or isinstance(src2, str):
            src = ord(src2)
        self.setRegister(dst, src1 ^ src2)
        self.calculateNextPC(ins)

    # opcode b7 12x xor-int/2addr vA, vB
    def _ins_xor_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        dst = self.getRegister(dst)
        if isinstance(dst, unicode) or isinstance(dst, str):
            dst = ord(dst)

        src = self.getRegister(src)
        if isinstance(src, unicode) or isinstance(src, str):
            src = ord(src)

        self.setRegister(self.getParametersValues(ins, 1), src ^ dst)
        self.calculateNextPC(ins)

    # opcode da 22b mul-int/lit8 vAA, vBB, #+CC
    def _ins_mul_int_lit8(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) * v)
        self.calculateNextPC(ins)

    # opcode d2 22s mul-int/lit16 vA, vB, #+CCCC
    def _ins_mul_int_lit16(self, ins):
        self._ins_mul_int_lit8(ins)

    # opcode 92 23x mul-int vAA, vBB, vCC
    def _ins_mul_int(self, ins):
        dst, src1 , src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src1) * self.getRegister(src2))
        self.calculateNextPC(ins)

    # opcode b2 12x mul-int/2addr vA, vB
    def _ins_mul_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(dst) * self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode 62 21c sget-object vAA, field@BBBB
    def _ins_sget_object(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        obj = self.dex.getField(src).getSignature(0)
        if obj in self.smaliInfos:
            obj = self.smaliInfos[obj]
        self.setRegister(dst, obj)
        self.calculateNextPC(ins)

    # opcode d1 22s rsub-int vA, vB, #+CCCC
    def _ins_rsub_int(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, v - self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode dc 22b rem-int/lit8 vAA, vBB, #+CC
    def _ins_rem_int_lit8(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) % v)
        self.calculateNextPC(ins)

    # opcode d4 22s rem-int/lit16 vA, vB, #+CCCC
    def _ins_rem_int_lit16(self, ins):
        self._ins_rem_int_lit8(ins)

    # opcode 94 23x rem-int vAA, vBB, vCC
    def _ins_rem_int(self, ins):
        dst, src1, src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src1) % self.getRegister(src2))
        self.calculateNextPC()

    # opcode b4 12x rem-int/2addr vA, vB
    def _ins_rem_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(dst) % self.getRegister(src))
        self.calculateNextPC()

    # opcode d9 22b rsub-int/lib8
    def _ins_rsub_int_lit8(self, ins):
        self._ins_rsub_int(ins)

    # opcode 8d 12x int-to-byte vA, vB
    def _ins_int_to_byte(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, cast_to_byte(self.getRegister(src)))
        self.calculateNextPC(ins)

    # opcode 8e 12x int-to-char vA, vB
    def _ins_int_to_char(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, cast_to_char(self.getRegister(src)))
        self.calculateNextPC(ins)

    # opcode e0 22b shl-int/lit8 vAA, vBB, #+CC
    def _ins_shl_int_lit8(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) << v)
        self.calculateNextPC(ins)

    # opcode 98 23x shl-int vAA, vBB, vCC
    def _ins_shl_int(self, ins):
        dst, src1, src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src1) << self.getRegister(src2))
        self.calculateNextPC(ins)

    # opcode b8 12x shl-int/2addr vA, vB
    def _ins_shl_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(dst) << self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode e2 22b shr-int/lit8 vAA, vBB, #+CC
    def _ins_shr_int_lit8(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) >> v)
        self.calculateNextPC(ins)

    # opcode 99 23x shr-int vAA, vBB, vCC
    def _ins_shr_int(self, ins):
        dst, src1, src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src1) >> self.getRegister(src2))
        self.calculateNextPC(ins)

    # opcode b9 12x shr-int/2addr vA, vB
    def _ins_shr_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(dst) >> self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode b0 12x add-int/2addr vA, vB
    def _ins_add_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(dst) + self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode 7b 12x neg-int vA, vB
    def _ins_neg_int(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, -self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode 7c 12x not-int vA, vB
    def _ins_not_int(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, ~self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode dd 22b and-int/lit8 vAA, vBB, #+CC
    def _ins_and_int_lit8(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) & v)
        self.calculateNextPC(ins)

    # opcode d5 22s and-int/lit16 vA, vB, #+CCCC
    def _ins_and_int_lit16(self, ins):
        self._ins_and_int_lit8(ins)

    # opcode 95 23x and-int vAA, vBB, vCC
    def _ins_and_int(self, ins):
        dst, src1, src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src1) & self.getRegister(src2))
        self.calculateNextPC(ins)

    # opcode b5 12x and-int/2addr vA, vB
    def _ins_and_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(dst) & self.getRegister(src))
        self.calculateNextPC(ins)

    # opcode de 22b or-int/lit8 vAA, vBB, #+CC
    def _ins_or_int_lit8(self, ins):
        dst, src, v = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src) | v)
        self.calculateNextPC(ins)

    # opcode d6 22s or-int/lit16 vA, vV, #+CCCC
    def _ins_or_int_lit16(self, ins):
        self._ins_or_int_lit8(ins)

    # opcode 96 23x or-int vAA, vBB, vCC
    def _ins_or_int(self, ins):
        dst, src1, src2 = self.getParametersValues(ins, 3)
        self.setRegister(dst, self.getRegister(src1) | self.getRegister(src2))
        self.calculateNextPC(ins)

    # opcode b6 12x or-int/2addr vA, vB
    def _ins_or_int_2addr(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        self.setRegister(dst, self.getRegister(dst) | self.getRegister(src))
        self.calculateNextPC(ins)

    #
    # Some java methods often called by decryptString() routines "emulated"
    # It's dirty but it does the job...
    #

    def _class_java_lang_String__toCharArray___C(self, params):
        self.setSpecialRegister("result-object", list(self.getRegister(params[0].getValue())))

    def _class_java_lang_String___init___C_V(self, params):
        dst = params[0].getValue()
        arg = params[1].getValue()
        self.setRegister(dst, self.getRegister(arg))

    def _class_java_lang_String__intern__Ljava_lang_String_(self, params):
        self.setSpecialRegister("result-object", self.getRegister(params[0].getValue()))

    def _class_java_lang_String___init___BI_V(self, params):
        dst = params[0].getValue()
        arg = params[1].getValue()
        self.setRegister(dst, "".join(map(chr, self.getRegister(arg))))
