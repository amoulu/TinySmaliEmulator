# -*- coding: utf-8 -*-
# Andre <sh4ka> Moulu / ge0n0sis.github.io
#
# Example of how to use TinySmaliEmulator with androguard to deobfuscate whatsapp string encryption
#

import sys
import logging

logging.basicConfig(
    filename='androguard_emulator.log',
    filemode="w",
    format='[%(asctime)-15s] [%(levelname)s] => %(message)s',
    level=logging.INFO)

logger = logging.getLogger("AndroguardEmulator")

sys.path.append("/home/sh4ka/ge0n0sis/androguard/")

from androlyze import *
from emulator import TinySmaliEmulator

class AndroguardTSI(TinySmaliEmulator):
    def __init__(self, d):
        self.dex = d
        self.breakpoints = {
            "before": {},
            "after": {},
            "offset": {}
        }

    def getParametersValues(self, ins, n, full=False):
        """
        Read up to the n first parameters of the specified instruction
        """
        out = []
        params = ins.get_operands()
        for i in range(n):
            if full:
                out.append(params[i])
            else:
                out.append(params[i][1])

        if len(out) == 1:
            return out[0]
        else:
            return out

    def _getInstructionName(self, ins):
        return ins.get_name()

    def _getInstructionSize(self, ins):
        return len(ins.get_raw())

    def _getInstructionParameters(self, ins):
        out = []
        for op in ins.get_operands():
            out.append([op[0],op[1]])
        return out

    def _getStringFromIndex(self, ins, index):
        return ins.cm.get_string(index)

    def disas(self, className, methodName):
        cl = self.dex.get_class(className)
        m = filter(lambda x: (x.get_name() + x.get_descriptor()) == methodName, cl.get_methods())[0]

        """
        In [20]: m.get_information()
        Out[20]: {'params': [(3, 'java.lang.String')], 'registers': (0, 2), 'return': 'boolean'}
        """

        methodInformation = m.get_information()
        self.smaliInfos["registerCount"] = methodInformation["registers"][-1] + 1
        self.smaliInfos["argumentCount"] = len(methodInformation["params"]) if "params" in methodInformation else 0

        logger.info("Disassembling %s->%s" % (className, methodName))
        logger.info(self.smaliInfos)

        offset = 0
        for ins in m.get_instructions():
            ins.offset = offset
            self.smali[offset] = ins

            if self._getInstructionName(ins) in ("packed-switch-payload", "sparse-switch-payload"):
                switchTable = {}
                for key, target in zip(ins.get_keys(), ins.get_targets()):
                    switchTable[key] = target
                self.smaliInfos["switchTable_%d" % ins.offset] = switchTable
            offset += self._getInstructionSize(ins)

        self.checkForInstructionsSupport()

    def emulateInstruction(self, ins):
        insName = self._getInstructionName(ins)
        print "[-] emulating %s %s" % (ins.get_name(), ins.get_output())

        internalInsName = self._mangleInstructionName(insName)
        if internalInsName in dir(self) and callable(getattr(self, internalInsName)):
            getattr(self, internalInsName)(ins)
        else:
            raise Exception("instruction not handled yet %s" % (insName))

    # opcode 2b 31t packed-switch vAA, +BBBBBBBB
    def _ins_packed_switch(self, ins):
        src, switchTable = self.getParametersValues(ins, 2)
        switchTable = self.smaliInfos["switchTable_%d" % (ins.offset + ins.get_ref_off()*2)]
        src = self.getRegister(src)
        if src in switchTable.keys():
            self.setSpecialRegister("pc", self.getSpecialRegister("pc") + (switchTable[src] * 2))
        else:
            self.calculateNextPC(ins)

    # opcode 22 21c new-instance vAA, type@BBBB
    def _ins_new_instance(self, ins):
        dst, dexType = self.getParametersValues(ins, 2, full=True)
        dst = dst[1]
        dexType = dexType[-1]
        self.setRegister(dst, "new instance of %s" % dexType)
        self.calculateNextPC(ins)

    # opcode 6e 35c invoke-virtual {vC, vD, vE, vF, vG}, meth@BBBB
    def _ins_invoke_virtual(self, ins):
        params = self._getInstructionParameters(ins)
        params = map(lambda x: x[1], params)
        # HACK!!1§! redo this with a proper way
        class_name, method_name = ins.get_operands()[-1][-1].split("->")
        internalMethodName = self._mangleMethodName(class_name, method_name)
        logger.info("trying to invoke %s %s as %s" % (class_name, method_name, internalMethodName))
        if internalMethodName in dir(self) and callable(getattr(self, internalMethodName)):
            getattr(self, internalMethodName)(params[:-1])
        else:
            raise Exception("call not handled yet %s" % (internalMethodName))
        self.calculateNextPC(ins)

    def _ins_sget_object(self, ins):
        dst, src = self.getParametersValues(ins, 2)
        obj = self.dex.getField(src).getSignature(0)
        if obj in self.smaliInfos:
            obj = self.smaliInfos[obj]
        self.setRegister(dst, obj)
        self.calculateNextPC(ins)

    def _class_java_lang_String__toCharArray___C(self, params):
        self.setSpecialRegister("result-object", list(self.getRegister(params[0])))

    def _class_java_lang_String___init___C_V(self, params):
        dst = params[0]
        arg = params[1]
        self.setRegister(dst, self.getRegister(arg))

    def _class_java_lang_String__intern__Ljava_lang_String_(self, params):
        self.setSpecialRegister("result-object", self.getRegister(params[0]))

    def _class_java_lang_String___init___BI_V(self, params):
        dst = params[0]
        arg = params[1]
        self.setRegister(dst, "".join(map(chr, self.getRegister(arg))))

def stop(emulator):
    print "End of the string decryption routine reached:"
    emulator.stop = True
    for idx, val in enumerate(emulator.getRegister(emulator.currentInstruction.AA)):
        print "entry %d: '%s'" % (idx, repr("".join(map(chr, val))))

def ipython(emulator):
    from IPython import embed;embed()

if __name__ == "__main__":
    class_name = "Lc;"
    method_name = "<clinit>()V"

    CONF["SESSION"] = Session(True)
    apk, d, dx = AnalyzeDex("poc.dex")

    tse = AndroguardTSI(d)
    tse.initialize(class_name, method_name)
    tse.cleanState()
    tse.addBreakpoint("before", "sput-object", stop)
    #tse.addBreakpoint("before", "invoke-virtual", ipython)
    tse.run([])


