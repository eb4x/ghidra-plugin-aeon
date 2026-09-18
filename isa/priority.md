# Decode priority rules applied by the generator

objdump takes the first matching table entry; SLEIGH takes the
most specific pattern. These constraints encode the difference.

- `bt.stack`: constraint `t_QMc_5_9!=0` — bt.trap/bt.nop take the encoding when the register field is 0
- `bn.lbz`: constraint `n_QMc_13_17!=0` — bn.pclwz takes the encoding when rD is 0
- `bn.mlwz`: constraint `n_Dc_13_17=0..31 & n_cc_0_1=0..3` — enumerated so the transferred registers are real registers in the p-code; c selects 2, 3, 4 or 8 registers (measured in aeon-elf-sim)
- `bn.msw`: constraint `n_Bc_13_17=0..31 & n_cc_0_1=0..3` — enumerated so the transferred registers are real registers in the p-code; c selects 2, 3, 4 or 8 registers (measured in aeon-elf-sim)
- `bg.lbz`: constraint `g_QMc_21_25!=0` — bg.pclwz takes the encoding when rD is 0
- `bg.lbs`: constraint `g_QMc_21_25!=0` — objdump rejects bg.lbs with rD 0
