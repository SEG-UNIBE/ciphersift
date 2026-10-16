from hashlib import *
import hashlib

s1 = hashlib
s2 = s1
s3 = s2
s4 = s3
s5 = s4
s6 = s5
s7 = s6
s8 = s7
s9 = s8
s10 = s9
s11 = s10
s12 = s11
s13 = s12
s14 = s13
s15 = s14
s16 = s15
s16.sha1(b"x")  # 20: 16 binding steps: hashlib.sha1
s17 = s16
s17.sha1(b"x")  # 22: 17 steps: unresolved, no finding

md5 = v
u0 = md5
u1 = u0
u2 = u1
u3 = u2
u4 = u3
u5 = u4
u6 = u5
u7 = u6
u8 = u7
u9 = u8
u10 = u9
u11 = u10
u12 = u11
u13 = u12
u14 = u13
u15 = u14
u15(b"x")  # 41: md5 is reached at step 16 and its own binding exceeds the limit: unresolved (O4), not md5 / hashlib.md5
