def cast_to_byte(a):
  t = a & 0xFF
  if t >= 0x80:
    return t - 0x100
  else:
    return t

def cast_to_ubyte(a):
  return a & 0xFF

def cast_to_short(a):
  t = a & 0xFFFF
  if t >= 0x8000:
    return t - 0x10000
  else:
    return t

def cast_to_char(a):
  return a & 0xFFFF

def cast_to_int(a):
  t = a & 0xFFFFFFFFFF
  if t >= 0x80000000:
    return t - 0x100000000
  else:
    return t

def cast_to_long(a):
  t = a & 0xFFFFFFFFFFFFFFFFFF
  if t >= 0x8000000000000000:
    return t - 0x10000000000000000
  else:
    return t
