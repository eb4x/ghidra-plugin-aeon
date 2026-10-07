# The smoke sample: one small program covering what smokeTest checks.
# Assembled and linked at 0x200000 by `./gradlew generateSmokeSample` with the
# vendor toolchain (local only); the bytes and the objdump listing it writes
# beside this file are committed, so CI needs neither.
#
# - every instruction length: 2, 3 and 4 bytes
# - an address passed to a callee (r3) and a struct base held in r11: AEON's
#   address analyzer references the second, the stock propagator does not
# - a value completed from r0, which must not become a reference
# - a b.jal callee, which analysis must turn into a function

	.text
	.global _start
_start:
	b.addi	r1,r1,-8
	b.sw	4(r1),r9
	b.sw	0(r1),r11
	b.movhi	r3,hi(greeting)
	b.addi	r3,r3,lo(greeting)
	b.jal	length
	b.movhi	r11,hi(counters)
	b.addi	r11,r11,lo(counters)
	b.lwz	r4,4(r11)
	b.add	r3,r3,r4
	b.sw	8(r11),r3
	b.addi	r5,r0,0x7000
	b.add	r3,r3,r5
	b.lwz	r11,0(r1)
	b.lwz	r9,4(r1)
	b.addi	r1,r1,8
	b.jr	r9

# length(s): the length of a NUL-terminated string
length:
	b.addi	r4,r3,0
1:	b.lbz	r5,0(r4)
	b.beqi	r5,0,2f
	b.addi	r4,r4,1
	b.j	1b
2:	b.sub	r3,r4,r3
	b.jr	r9

	.data
	.align	2
counters:
	.word	0, 41, 0
greeting:
	.asciz	"smoke"
