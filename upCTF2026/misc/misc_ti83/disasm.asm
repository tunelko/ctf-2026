; z80dasm 1.1.6
; command line: z80dasm -a -l -g 0x9D95 z80_code.bin

	org	09d95h

	jp l9e57h		;9d95
l9d98h:
	ld h,l			;9d98
	jp pe,0ce10h		;9d99
	dec a			;9d9c
	defb 0ddh,0bbh,08fh	;illegal sequence		;9d9d
	inc hl			;9da0
	ld b,l			;9da1
	call pe,092a7h		;9da2
	and l			;9da5
	xor d			;9da6
	ld a,(de)			;9da7
	ld l,d			;9da8
	ld h,(hl)			;9da9
l9daah:
	ld (hl),d			;9daa
	or (hl)			;9dab
	ld e,c			;9dac
	ld hl,06cdeh		;9dad
	sbc a,b			;9db0
	sub a			;9db1
	and l			;9db2
	ld c,c			;9db3
	rra			;9db4
	ret pe			;9db5
	exx			;9db6
	ld c,0b5h		;9db7
	add a,h			;9db9
	or h			;9dba
	or a			;9dbb
	ld d,(hl)			;9dbc
	add a,(hl)			;9dbd
	ld e,c			;9dbe
	ld hl,0a176h		;9dbf
	or l			;9dc2
	cp l			;9dc3
	add hl,de			;9dc4
	add a,a			;9dc5
	or a			;9dc6
	add a,h			;9dc7
	or h			;9dc8
	or a			;9dc9
	ld e,a			;9dca
	add a,(hl)			;9dcb
	ld e,c			;9dcc
	ld hl,0b5a1h		;9dcd
	ex af,af'			;9dd0
	ret nc			;9dd1
	add a,h			;9dd2
	or a			;9dd3
	ld e,e			;9dd4
	nop			;9dd5
	ld l,(hl)			;9dd6
	add a,(hl)			;9dd7
	ld e,c			;9dd8
	ld hl,0b5a1h		;9dd9
	ex af,af'			;9ddc
	ret nc			;9ddd
	add a,h			;9dde
	or a			;9ddf
	ld e,e			;9de0
	sub b			;9de1
	ld l,(hl)			;9de2
l9de3h:
	nop			;9de3
l9de4h:
	nop			;9de4
l9de5h:
	dec a			;9de5
	jr nz,l9e2bh		;9de6
	ld c,a			;9de8
	ld b,h			;9de9
	ld b,l			;9dea
	jr nz,$+69		;9deb
	ld c,b			;9ded
	ld b,l			;9dee
	ld b,e			;9def
	ld c,e			;9df0
	ld b,l			;9df1
	ld d,d			;9df2
	jr nz,l9e32h		;9df3
	nop			;9df5
l9df6h:
	ld b,l			;9df6
	ld l,(hl)			;9df7
	ld (hl),h			;9df8
	ld h,l			;9df9
	ld (hl),d			;9dfa
	jr nz,$+101		;9dfb
	ld l,a			;9dfd
	ld h,h			;9dfe
	ld h,l			;9dff
	jr nz,$+42		;9e00
	ld b,e			;9e02
	ld c,h			;9e03
	ld b,l			;9e04
	ld b,c			;9e05
	ld d,d			;9e06
	dec a			;9e07
	ld (hl),d			;9e08
	ld h,l			;9e09
	ld (hl),e			;9e0a
	ld h,l			;9e0b
	ld (hl),h			;9e0c
	add hl,hl			;9e0d
	ld a,(03e00h)		;9e0e
	jr nz,l9e13h		;9e11
l9e13h:
	ld b,e			;9e13
	ld c,a			;9e14
	ld d,d			;9e15
	ld d,d			;9e16
	ld b,l			;9e17
	ld b,e			;9e18
	ld d,h			;9e19
	ld hl,03a20h		;9e1a
	add hl,hl			;9e1d
	nop			;9e1e
l9e1fh:
	ld d,a			;9e1f
	ld d,d			;9e20
	ld c,a			;9e21
	ld c,(hl)			;9e22
	ld b,a			;9e23
	ld l,020h		;9e24
	ld d,h			;9e26
	ld (hl),d			;9e27
	ld a,c			;9e28
	jr nz,$+99		;9e29
l9e2bh:
	ld h,a			;9e2b
	ld h,c			;9e2c
	ld l,c			;9e2d
	ld l,(hl)			;9e2e
	ld l,000h		;9e2f
l9e31h:
	exx			;9e31
l9e32h:
	ex af,af'			;9e32
	ld a,(09872h)		;9e33
	or a			;9e36
	jr z,l9e52h		;9e37
	xor a			;9e39
	ld (09872h),a		;9e3a
	ld a,(l9de3h)		;9e3d
	or a			;9e40
	jr z,l9e52h		;9e41
	ld b,a			;9e43
	ld a,(08749h)		;9e44
l9e47h:
	srl a		;9e47
	jr nc,l9e4dh		;9e49
	xor 0b8h		;9e4b
l9e4dh:
	djnz l9e47h		;9e4d
	ld (08749h),a		;9e4f
l9e52h:
	ex af,af'			;9e52
	exx			;9e53
	jp 00038h		;9e54
l9e57h:
	rst 28h			;9e57
	ld b,b			;9e58
	ld b,l			;9e59
	ld a,008h		;9e5a
	ld (086d8h),a		;9e5c
	ld a,00ah		;9e5f
	ld (086d7h),a		;9e61
	ld hl,l9de5h		;9e64
	rst 28h			;9e67
	ld h,c			;9e68
	ld b,l			;9e69
	ld a,014h		;9e6a
	ld (086d8h),a		;9e6c
	xor a			;9e6f
	ld (086d7h),a		;9e70
	ld hl,l9df6h		;9e73
	rst 28h			;9e76
	ld h,c			;9e77
	ld b,l			;9e78
	ld a,020h		;9e79
	ld (086d8h),a		;9e7b
	xor a			;9e7e
	ld (086d7h),a		;9e7f
	ld hl,09e10h		;9e82
	rst 28h			;9e85
	ld h,c			;9e86
	ld b,l			;9e87
	ld a,(086d7h)		;9e88
	ld (l9de4h),a		;9e8b
	xor a			;9e8e
	ld (l9de3h),a		;9e8f
	ld a,0a5h		;9e92
	ld (08749h),a		;9e94
	xor a			;9e97
	ld (09872h),a		;9e98
	di			;9e9b
	ld hl,09900h		;9e9c
	ld de,09901h		;9e9f
	ld bc,00100h		;9ea2
	ld (hl),09ah		;9ea5
	ldir		;9ea7
	ld hl,l9e31h		;9ea9
	ld de,09a9ah		;9eac
	ld bc,00026h		;9eaf
	ldir		;9eb2
	ld a,099h		;9eb4
	ld i,a		;9eb6
	im 2		;9eb8
	ei			;9eba
l9ebbh:
	ld a,001h		;9ebb
	ld (09872h),a		;9ebd
	rst 28h			;9ec0
	ld (hl),d			;9ec1
	ld c,c			;9ec2
	cp 040h		;9ec3
	jp z,l9f83h		;9ec5
	cp 005h		;9ec8
	jr z,l9f18h		;9eca
	cp 009h		;9ecc
	jr z,l9ef2h		;9ece
	ld c,a			;9ed0
	call sub_9f8bh		;9ed1
	jr c,l9ebbh		;9ed4
	ld a,(l9de3h)		;9ed6
	cp 012h		;9ed9
	jr nc,l9ebbh		;9edb
	ld hl,086ech		;9edd
	ld d,000h		;9ee0
	ld e,a			;9ee2
	add hl,de			;9ee3
	ld (hl),c			;9ee4
	inc a			;9ee5
	ld (l9de3h),a		;9ee6
	ld a,c			;9ee9
	call sWarning: Code might not be 8080 compatible!
ub_9fa1h		;9eea
	rst 28h			;9eed
	ld e,(hl)			;9eee
	ld b,l			;9eef
	jr l9ebbh		;9ef0
l9ef2h:
	di			;9ef2
	ld a,0a5h		;9ef3
	ld (08749h),a		;9ef5
	xor a			;9ef8
	ld (l9de3h),a		;9ef9
	xor a			;9efc
	ld (09872h),a		;9efd
	ei			;9f00
	ld a,(l9de4h)		;9f01
	ld (086d7h),a		;9f04
	ld b,013h		;9f07
l9f09h:
	ld a,020h		;9f09
	rst 28h			;9f0b
	ld e,(hl)			;9f0c
	ld b,l			;9f0d
	djnz l9f09h		;9f0e
	ld a,(l9de4h)		;9f10
	ld (086d7h),a		;9f13
	jr l9ebbh		;9f16
l9f18h:
	ld a,(l9de3h)		;9f18
	cp 012h		;9f1b
	jr nz,l9f53h		;9f1d
	di			;9f1f
	im 1		;9f20
	ei			;9f22
	ld a,(08749h)		;9f23
	xor 017h		;9f26
	ld c,a			;9f28
	ld hl,l9daah		;9f29
	ld de,08710h		;9f2c
	ld b,039h		;9f2f
l9f31h:
	ld a,(hl)			;9f31
	xor c			;9f32
	ld (de),a			;9f33
	inc hl			;9f34
	inc de			;9f35
	djnz l9f31h		;9f36
	ld hl,l9d98h		;9f38
	ld de,086ech		;9f3b
	ld b,012h		;9f3e
	ld c,0a5h		;9f40
	call 08710h		;9f42
	push af			;9f45
	ld hl,08710h		;9f46
	ld b,039h		;9f49
	xor a			;9f4b
l9f4ch:
	ld (hl),a			;9f4c
	inc hl			;9f4d
	djnz l9f4ch		;9f4e
	pop af			;9f50
	jr nc,l9f6ch		;9f51
l9f53h:
	di			;9f53
	im 1		;9f54
	ei			;9f56
	ld a,02ch		;9f57
	ld (086d8h),a		;9f59
	xor a			;9f5c
	ld (086d7h),a		;9f5d
	ld hl,l9e1fh		;9f60
	rst 28h			;9f63
	ld h,c			;9f64
	ld b,l			;9f65
	rst 28h			;9f66
	ld (hl),d			;9f67
	ld c,c			;9f68
	jp l9e57h		;9f69
l9f6ch:
	di			;9f6c
	im 1		;9f6d
	ei			;9f6f
	ld a,02ch		;9f70
	ld (086d8h),a		;9f72
	xor a			;9f75
	ld (086d7h),a		;9f76
	ld hl,l9e13h		;9f79
	rst 28h			;9f7c
	ld h,c			;9f7d
	ld b,l			;9f7e
	rst 28h			;9f7f
	ld (hl),d			;9f80
	ld c,c			;9f81
	ret			;9f82
l9f83h:
	di			;9f83
	im 1		;9f84
	ei			;9f86
	rst 28h			;9f87
	daa			;9f88
	ld b,b			;9f89
	ret			;9f8a
sub_9f8bh:
	cp 08eh		;9f8b
	jr c,l9f95h		;9f8d
	cp 098h		;9f8f
	jr nc,l9f95h		;9f91
	and a			;9f93
	ret			;9f94
l9f95h:
	cp 09ah		;9f95
	jr c,l9f9fh		;9f97
	cp 0b4h		;9f99
	jr nc,l9f9fh		;9f9b
	and a			;9f9d
	ret			;9f9e
l9f9fh:
	scf			;9f9f
	ret			;9fa0
sub_9fa1h:
	cp 08eh		;9fa1
	jr c,l9faeh		;9fa3
	cp 098h		;9fa5
	jr nc,l9faeh		;9fa7
	sub 08eh		;9fa9
	add a,030h		;9fab
	ret			;9fad
l9faeh:
	cp 09ah		;9fae
	jr c,l9fbbh		;9fb0
	cp 0b4h		;9fb2
	jr nc,l9fbbh		;9fb4
	sub 09ah		;9fb6
	add a,041h		;9fb8
	ret			;9fba
l9fbbh:
	ld a,03fh		;9fbb
	ret			;9fbd
