# Decode priority rules applied by the generator

objdump takes the first matching table entry; SLEIGH takes the
most specific pattern. These constraints encode the difference.

- `bt.stack`: constraint `t_QMc_5_9!=0` — bt.trap/bt.nop take the encoding when the register field is 0
- `bn.lbz`: constraint `n_QMc_13_17!=0` — bn.pclwz takes the encoding when rD is 0
- `bg.lbz`: constraint `g_QMc_21_25!=0` — bg.pclwz takes the encoding when rD is 0
- `bg.lbs`: constraint `g_QMc_21_25!=0` — objdump rejects bg.lbs with rD 0
