# -*- coding: utf-8 -*-
# Andre <sh4ka> Moulu / ge0n0sis.github.io
#
# This JEB Plugin emulate part of the dalvik instruction set and JEB's AST
# to desobfuscate Dexguard 6.x strings.
#
# Please keep in mind this is only a PoC ...
#

import sys
import os
import time

from jeb.api import IScript
from jeb.api import EngineOption
from jeb.api.ast import Class, Field, Method, Call, Constant, StaticField, NewArray, Identifier, ArrayElt, Expression, \
    Definition, Assignment, InstanceField, Block
from jeb.api.dex import Dex
from jeb.api.ui import View
from jeb.api.ui.JebUI import ButtonGroupType
from jeb.api.ui.JebUI import IconType

from emulator import TinySmaliEmulator
from jebAST import AST

import logging

logging.basicConfig(
    filename='dexguard-jeb.log',
    filemode="w",
    format='[%(asctime)-15s] [%(levelname)s] => %(message)s',
    level=logging.DEBUG)
logger = logging.getLogger("JEBPlugin")


class DexguardEmulator(IScript):
    encbytesValue = []
    encbytesSignature = ""
    magicValue = None
    magicValueSignature = ""
    decryptSignature = ""

    def run(self, jeb):
        self.jeb = jeb
        self.ui = jeb.getUI()
        self.dex = self.jeb.getDex()
        self.handleAST = AST(self)
        self.emulator = TinySmaliEmulator(self)
        self.cstbuilder = Constant.Builder(jeb)
        self.strings = {}

        self.runOnCurrentClass()
        # self.runOnAllClasses()

        for string in self.strings:
            logger.debug("Setting comment '%s' for '%s'" % (', '.join(self.strings[string]), string))
            self.jeb.setInstructionComment(string, 0, ', '.join(self.strings[string]))

    # Heuristic: try to find the decrypt method by looking for something similar to:
    # byte v5[] = I.encBytes
    def findDecryptMethod(self, classTree, encBytesSignature):
        # Loop over methods in the current class
        for method in classTree.getMethods():
            # Loop over methods blocks
            block = method.getBody()
            for i in range(0, block.size()):
                # Analyse each statement searching for the pattern
                st = block.get(i)
                if isinstance(st, Assignment) is True and st.isSimpleAssignment():
                    left = st.getLeft()
                    right = st.getRight()
                    if isinstance(right, StaticField) is True and left.getType() in ("[B", "[S"):
                        decryptMethodSignature = method.getSignature()
                        return decryptMethodSignature

    def runOnCurrentClass(self):
        # get the current class name
        if self.ui.isViewVisible(View.Type.JAVA) is False:
            self.ui.displayMessageBox("Error", "You must have focus on the Java view!", IconType.ERROR,
                                      ButtonGroupType.OK)
            return

        java = self.ui.getView(View.Type.JAVA)
        codePosition = java.getCodePosition()
        class_name = codePosition.getSignature().split("->")[0]
        print "Analyzing %s" % class_name

        r = self.jeb.decompileClass(class_name)
        if not r:
            print "Could not find class '%s'" % class_name
            return

        ct = self.jeb.getDecompiledClassTree(class_name)

        possible_candidates = {}
        wanted_flags = Dex.ACC_PRIVATE | Dex.ACC_STATIC | Dex.ACC_FINAL
        for f in ct.getFields():
            fsig = f.getSignature()
            print fsig
            if fsig.endswith(':[B') or fsig.endswith(":[S"):
                fd = self.dex.getFieldData(fsig)
                if fd.getAccessFlags() & wanted_flags == wanted_flags:
                    findex = fd.getFieldIndex()
                    possible_candidates[fsig] = len(self.dex.getFieldReferences(findex))
                    print 'Found a possible encBytes: %s (%d)' % (fsig, possible_candidates[fsig])

        fsig = max(possible_candidates, key=possible_candidates.get)
        self.encbytesSignature = fsig
        print "the good encBytes should be: %s" % self.encbytesSignature

        # get encBytes value
        for m2 in ct.getMethods():
            if m2.getName() != "<clinit>":
                continue
            block = m2.getBody()
            i = 0
            while i < block.size() and i < 10:
                stm = block.get(i)
                # print stm
                if isinstance(stm, Assignment) and stm.isSimpleAssignment():
                    print "%s = %s" % (stm.getLeft(), stm.getRight())
                    left = stm.getLeft()
                    right = stm.getRight()
                    if left.getField().getSignature() == self.encbytesSignature:
                        print "Found assignment of an encBytes"
                        self.encbytesValue = map(lambda x: self.handleAST.evalExpression(x), right.getInitialValues())
                        print self.encbytesValue

                        print "Trying to get magic value"
                        if block.size() < (i + 1):
                            print "no magic value"
                            break

                        stm2 = block.get(i + 1)
                        assert isinstance(stm2.getRight(), Constant) == True
                        left, right = stm2.getLeft(), stm2.getRight()
                        self.magicValue = self.handleAST.evalExpression(right)
                        self.magicValueSignature = left.getField().getSignature()
                        break
                i += 1

        # try to detect decrypt method
        found = False
        for m2 in ct.getMethods():
            if found is not True:
                block = m2.getBody()
                i = 0
                while i < block.size():
                    stm = block.get(i)
                    print stm
                    if isinstance(stm, Assignment) and stm.isSimpleAssignment():
                        if isinstance(stm.getRight(), StaticField) is True and isinstance(stm.getLeft(),
                                                                                          Definition) and stm.getLeft().getType() in (
                        "[B", "[S"):
                            left = stm.getLeft()
                            right = stm.getRight()

                            print "%s = %s" % (left, right)
                            if self.encbytesSignature == right.getField().getSignature():
                                print "Decrypt method found! %s" % (m2.getSignature())
                                self.decryptSignature = m2.getSignature()
                                found = True
                                break
                    i += 1

        assert self.decryptSignature != ""

        class_name, method_name = self.decryptSignature.split("->")
        print class_name
        print method_name

        self.emulator.initialize(class_name, method_name)
        self.emulator.smaliInfos[self.encbytesSignature] = self.encbytesValue
        for m in ct.getMethods():
            print "\t - method: %s" % (m.getSignature())
            if m.getSignature() == self.decryptSignature:
                print "decrypt, skip"
                continue
            self.handleAST.resetMethodState()
            self.decryptMethodStrings(class_name, m)

    def decryptMethodStrings(self, class_name, m):
        block = m.getBody()
        i = 0
        while i < block.size():
            stm = block.get(i)
            self.checkElement(block, stm, class_name, m)
            i += 1

    def evalArg(self, arg):
        return self.handleAST.evalExpression(arg)

    def checkElement(self, parent, e, class_name, m):
        if isinstance(e, Assignment):
            self.handleAST.evalExpression(e)

        if isinstance(e, Call):
            method_signature = e.getMethod().getSignature()

            if method_signature == self.decryptSignature:
                print "Found a call to decrypt"
                args = []
                for i in range(3):
                    arg = e.getArguments()[i]
                    argValue = self.evalArg(arg)
                    args.append(argValue)

                try:
                    print "decrypt(%d,%d,%d)" % (args[0], args[1], args[2])
                    decrypted_string = self.decrypt(*args)

                    if not isinstance(parent, Block):
                        parent.replaceSubElement(e, self.cstbuilder.buildString(decrypted_string))

                    method = m.getSignature()
                    if not method in self.strings:
                        self.strings[method] = set()
                    self.strings[method].add(decrypted_string)
                except Exception, err:
                    logger.error("[*] Error: method %s (%s)" % (e.getMethod().getSignature(), str(err)))

        for subelt in e.getSubElements():
            if isinstance(subelt, Class) or isinstance(subelt, Field) or isinstance(subelt, Method) or isinstance(
                    subelt, Identifier):
                continue
            self.checkElement(e, subelt, class_name, m)

    def decrypt(self, arg1, arg2, arg3):
        self.emulator.cleanState()
        self.emulator.run([arg1, arg2, arg3])
        return self.emulator.getResult()
