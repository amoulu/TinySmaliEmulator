# TinySmaliEmulator

## TL;DR
A very minimalist smali emulator that could be used to decrypt obfuscated strings.

This repo is composed of:
- emulator.py, a basic smali emulator.
- AndroguardEmulator.py, an example of how to use this emulator in androguard to deobfuscate whatsapp strings.
- poc.dex, a class extracted from a whatsapp obfuscated version used by AndroguardEmulator.py to demo how it works.
- DexguardEmulator.py, an example of how to use this emulator in JEB1 to deobfuscate strings protected by Dexguard 6.X.
- jebAST.py, a basic JEB AST evaluator used by DexguardEmulator.py to try to discover the real values of parameters passed to the decryptString() functions.

**Beware: this is really a dirty code, please keep in mind it was only a PoC.**

## Longer version

I wrote this initially to deal with Dexguard 6.x string obfuscation scheme. 

When you have to deal with Dexguard 6.X, for each class with obfuscated strings, you have to find several elements:
- a magic (a random int)
- an "encrypted" array of bytes
- a decryptString() method

For example:

![dexguard_sample.png](https://github.com/amoulu/TinySmaliEmulator/blob/master/img/dexguard_sample.png)

In Dexguard 6.X, these different elements will have a different name in each protected class. Moreover, decryptString() for each class will have some variation in its implementation, you can't just reimplement it in python and use it for the entire APK. To solve this problem, I developped a basic smali emulator that will run decryptString() functions and return the deobfuscated strings.

But you also have to deal with the fact that Dexguard do now some calculation on the paramaters passed to decryptString(), you can't have directly the values as before.

For example, before you had things like:

```
decryptString(40,10,-2);
decryptString(1,-5,60);
```

Now you have things like:

```
decryptString(40, X.encBytes[12], (X.encBytes[9] & 8) + X.randomByte);
decryptString(0, (short)-X.encBytes[6], 10);
int v0 = 10; 
byte[] v1 = X.encBytes; 
v2 = v1[90]; 
decryptString(v2, v1[40] + v0, v1[2] >> X.randomByte);
```
To solve this problem I developped also a basic JEB AST evaluator to "calculate" the final values passed to decryptString() functions.

Finally I put these two modules in a JEB1 Plugin (``DexguardEmulator.py``). This plugin will identify for the current class (it can obviously be automated to all the classes in the APK) the important Dexguards elements (the magic, the encrypted array of byte and the decryptString() method), then for each call to decryptString() it will use the AST evaluator to get the true values passed as paramaters and finally it will run the smali emulator on decryptString() with the previously discovered parameters. And thanks to the powerfull JEB1 AST API, it replaces every call to decryptString() by the deobfuscated string.

An example of the result:

![dexguard_result.png](https://github.com/amoulu/TinySmaliEmulator/blob/master/img/dexguard_result.png)

## Bonus

I also made a PoC to use the emulator in Androguard, it's implemented in ``AndroguardEmulator.py``. This time, we will take whatsapp string obfuscation as a target.

I extracted a single obfuscated class from a Whatsapp APK file and put it in poc.dex to demo the Androguard emulation.

Basically, at runtime, the obfuscator will deobfuscate every strings used in the current class in a array of String and this is done in the ``<clinit>`` method of the class. If the original class has already some code in the ``<clinit>`` method, the obfuscator just prepend its deobfuscation code. 

I will not explain the obfuscation here, you can have a look at poc.dex, it's really easy. You just have to know that the deobfuscation code finish with a ``sput-object`` smali instruction to place the deobfuscated array of String into a static array of String. Then, each time the application will need to use a deobfuscated string, it will reference an entry in the static array of String.

This time, in order to deobfuscate the strings, we just have to let the emulator execute the ``<clinit>`` method. To not have to deal with already existing complex code in ``<clinit>`` just after the debofuscation code, we can put a breakpoint in the emulator on the instruction ``sput-object``, print the deobfuscated strings and stop the emulation.

Below is an example of output of the ``AndroguardEmulator.py`` script on poc.dex:

![androguard_result.png](https://github.com/amoulu/TinySmaliEmulator/blob/master/img/androguard_result.png)
