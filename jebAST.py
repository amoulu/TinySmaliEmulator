# -*- coding: utf-8 -*-
# Andre <sh4ka> Moulu / ge0n0sis.github.io
#
# This is a minimalist JEB AST Evaluation module.
# It is used to get the real parameters values
# passed to decryptString() calls.
#
# Please keep in mind this is only a PoC ...
#

from jeb.api.ast import Class, Field, Method, Call, Constant, StaticField, NewArray, Identifier, ArrayElt, Expression, \
    Definition, Assignment, InstanceField

from IntCast import *

import logging

logging.basicConfig(
    filename='jeb_ast.log',
    filemode="w",
    format='[%(asctime)-15s] [%(levelname)s] => %(message)s',
    level=logging.DEBUG)
logger = logging.getLogger("JEBPlugin")


class AST():
    methodState = {}

    def __init__(self, plugin):
        self.plugin = plugin

    def resetMethodState(self):
        self.methodState = {}

    def evalConstant(self, constant):
        ty = constant.getType()
        if ty == "Z":
            return constant.getBoolean()
        elif ty == "B":
            return constant.getByte()
        elif ty == "S":
            return constant.getShort()
        elif ty == "C":
            return constant.getChar()
        elif ty == "I":
            return constant.getInt()
        elif ty == "J":
            return constant.getLong()
        elif ty == "F":
            return constant.getFloat()
        elif ty == "D":
            return constant.getDouble()
        elif ty == "java.lang.String":
            return constant.getString()
        return None

    def evalArithBooleansExpression(self, left, operator, right):
        if operator.toString() == "+":
            return left + right
        if operator.toString() == "-":
            return left - right
        if operator.toString() == "*":
            return left * right
        if operator.toString() == "/":
            return left / (right * 1.0)
        if operator.toString() == "|":
            return left | right
        if operator.toString() == "&":
            return left & right
        if operator.toString() == "<<":
            return left << right
        if operator.toString() == ">>":
            return left >> right
        if operator.toString() == ">>>":
            return (left % 0x100000000) >> right

    def evalCast(self, operator, right):
        if right is None:
            return None
        casts = {
            "(byte)": self.castByte,
            "(short)": self.castShort,
            "(int)": self.castInt,
            "(long)": self.castLong
        }
        if operator.toString() in casts.keys():
            return casts[operator.toString()](right)
        else:
            return right

    def evalAssignment(self, exp):
        left = exp.getLeft()
        right = exp.getRight()
        if exp.isSimpleAssignment() is not True:
            logger.debug("Not a simple Assignment, skipping...")
            return None

        if isinstance(right, Constant) and (isinstance(left, Definition) or isinstance(left, Identifier)):
            if isinstance(left, Definition):
                left = left.getIdentifier()
            if right.getType() in ["Z", "B", "S", "C", "I", "J", "F", "D", "java.lang.String"]:
                rightValue = self.evalExpression(right)
                self.methodState[left.getName()] = rightValue
                logger.debug("Adding new content to methodState: %s => %s" % (left.getName(), rightValue))
            return None

        if isinstance(right, Call):
            logger.debug("Assignment is the result of a call, skipping...")
            return None

        if isinstance(right, StaticField):
            if right.getField().getSignature() == self.plugin.encbytesSignature:
                self.methodState[left.getName()] = self.plugin.encbytesValue
                logger.debug("Adding new content to methodState: %s => %s" % (left.getName(), self.plugin.encbytesValue))
            else:
                logger.debug("Assignment of a StaticField seems not to meet the heuristic, skipping...")
            return None

        if isinstance(right, Expression) is not True and isinstance(right, ArrayElt) is not True:
            logger.debug("Assignment seems not to meet the heuristic, skipping...")
            logger.debug(right)
            return None

        if isinstance(left, Definition):
            if isinstance(left, ArrayElt):
                logger.debug("Assignment of ArrayElt not handled yet, skipping...")
                return None
            dst = left.getIdentifier().getName()
        else:
            if isinstance(left, ArrayElt):
                logger.debug("Assignment of ArrayElt not handled yet, skipping...")
                return None
            if isinstance(left, InstanceField) or isinstance(left, StaticField):
                dst = left.getField().getName()
            else:
                dst = left.getName()
        value = self.evalExpression(right)
        logger.debug("%s = %s" % (dst, str(value)))
        if isinstance(value, int) or isinstance(value, long):
            self.methodState[dst] = value
            logger.debug("Adding new content to methodState: %s => %s" % (dst, value))
            return None

    def evalExpression(self, exp):
        if exp is None:
            return None

        logger.debug("trying to evaluate : %s" % (exp.toString()))

        if isinstance(exp, str):
            return exp

        elif isinstance(exp, Constant):
            return self.evalConstant(exp)

        elif isinstance(exp, Expression):
            left = self.evalExpression(exp.getLeft())
            operator = exp.getOperator()
            right = self.evalExpression(exp.getRight())

            logger.debug("Expression => %s %s %s" % (left, operator, right))

            # handle casts
            if left is None and operator.toString()[0] == "(":
                return self.evalCast(operator, right)

            # handle arithmetics and booleans expressions
            if left is None:
                left = 0
            if right is None:
                right = 0
            return self.evalArithBooleansExpression(left, operator, right)

        elif isinstance(exp, StaticField):
            f = exp.getField()
            if f.getSignature() == self.plugin.magicValueSignature:
                return self.plugin.magicValue

        elif isinstance(exp, ArrayElt):
            # This can be an alias of encbyte, like v1_1 = ﯧ.encBytes; byte v1_2 = ((byte)(-v1_1[59]));
            if isinstance(exp.getArray(), Identifier):
                name = exp.getArray().getName()
                offset = self.evalExpression(exp.getIndex())
                if name in self.methodState:
                    return self.methodState[name][offset]
                else:
                    logger.debug("No value found in methodState for %s[%s]" % (name, offset))
                    return None
            else:
                array = exp.getArray().getField()
                offset = self.evalExpression(exp.getIndex())
                if array.getSignature() == self.plugin.encbytesSignature:
                    return self.plugin.encbytesValue[offset]
                else:
                    logger.debug("ArrayElt ignored: %s" % (array.getSignature()))
                    return None

        elif isinstance(exp, Assignment):
            return self.evalAssignment(exp)

        elif isinstance(exp, Identifier):
            if exp.getName() in self.methodState:
                logger.debug("Looking for a value for %s. Found in methodState ! => %s" % (exp.getName(), self.methodState[exp.getName()]))
                return self.methodState[exp.getName()]
            else:
                logger.debug("No value found in methodState for %s :(" % (exp.getName()))
                return None

        elif isinstance(exp, Call):
            logger.debug("Call not handled yet %s" % (exp.getMethod().getName()))
            return None

        elif isinstance(exp, InstanceField):
            if exp.getInstance().getField().getSignature() == self.plugin.encbytesSignature and exp.getField().getName() == "length":
                return len(self.plugin.encbytesValue)
            else:
                logger.debug("This kind of InstanceField is not handled yet...")
            return None

        else:
            raise Exception("%s [%s] not handled yet!" % (exp, type(exp)))

        return None

    def castByte(self, arg):
        if arg != None:
            return cast_to_byte(arg)
        return None

    def castShort(self, arg):
        if arg != None:
            return cast_to_short(arg)
        return None

    def castInt(self, arg):
        if arg != None:
            return cast_to_int(arg)
        return None

    def castLong(self, arg):
        if arg != None:
            return cast_to_long(arg)
        return None
