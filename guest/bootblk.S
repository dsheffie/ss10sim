/* A sun4m boot block for the OBP disk-boot test: OBP's "boot disk" reads it
 * from sectors 1-15 of the Sun-labelled disk, strips its a.out header, and
 * runs it at 0x4000 with the romvec in %o0.  The SS-20's OBP 2.25 romvec is
 * version 3: the v0 entries (pv_printf, pv_putstr, ...) are null, so it prints
 * by having the PROM evaluate Forth (pv_fortheval, v2 form, offset 124), then
 * goes back to the PROM through pv_halt (offset 116).  Position independent:
 * the string is addressed from the pc. */
	.text
	.globl	_start
_start:
	save	%sp, -96, %sp
	ld	[%i0 + 124], %l0	/* pv_fortheval: v2_eval(char *str) */
0:	call	1f			/* %o7 = 0b */
	 nop
1:	add	%o7, msg - 0b, %o0
	call	%l0
	 nop
	/* OBP jumped here (%o7 = 0): leave through pv_halt, back to the ok prompt */
	ld	[%i0 + 116], %l0
	call	%l0
	 nop
msg:	.asciz	".\" bootblk: running from the SCSI disk's boot block, loaded by OBP\" cr"
	.balign	4, 0
