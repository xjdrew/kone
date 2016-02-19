//
//   date  : 2016-02-19
//   author: xjdrew
//

// +build go1.2

TEXT	·socketcall(SB),4,$0-36
	JMP	syscall·socketcall(SB)
