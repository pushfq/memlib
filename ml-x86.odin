package memlib

Mode :: enum u8 {
	Mode_32,
	Mode_64,
}

Encoding :: enum u8 {
	Legacy,
	VEX,
	EVEX,
	XOP,
}

MAX_INST_LEN :: 15

Inst :: struct {
	length:       u8,
	encoding:     Encoding,
	mnemonic:     Mnemonic,
	prefix_seg:   u8,
	prefix_66:    bool,
	prefix_67:    bool,
	prefix_f0:    bool,
	prefix_f2:    bool,
	prefix_f3:    bool,
	prefix_fwait: bool,
	rex:          u8,
	rex_w:        bool,
	vex:          [3]u8,
	evex:         [4]u8,
	opcode:       [3]u8,
	opcode_len:   u8,
	modrm:        u8,
	sib:          u8,
	has_modrm:    bool,
	has_sib:      bool,
	disp_size:    u8,
	imm_size:     u8,
	imm2_size:    u8,
	operand_size: u8,
	address_size: u8,
	isa:          ISA_Ext,
}

decode_length :: proc "contextless" (data: []u8, mode: Mode) -> int {
	if len(data) == 0 do return 0

	pos := 0
	prefix_state := 0
	has_66 := false
	has_67 := false

	for pos < len(data) && pos < MAX_INST_LEN {
		b := data[pos]
		p := prefix_table[b]

		if p & 0xF0 == 0xF0 do break

		new_state := int(p >> 4)
		if new_state != 0 do prefix_state = new_state

		if b == 0x66 do has_66 = true
		if b == 0x67 do has_67 = true

		pos += 1
	}

	if mode == .Mode_64 && pos < len(data) {
		b := data[pos]
		if b >= 0x40 && b <= 0x4F do pos += 1
	}

	if pos >= len(data) do return 0
	opcode := data[pos]
	pos += 1

	ent := decode_map_1[prefix_state][opcode]
	desc := u8(ent.desc)

	escape := desc & u8(DESC_ESCAPE_MASK)
	if escape != 0 {
		if pos >= len(data) do return 0
		opcode = data[pos]
		pos += 1

		switch escape {
		case u8(DESC_ESCAPE_0F):
			if opcode == 0x38 {
				if pos >= len(data) do return 0
				opcode = data[pos]
				pos += 1
				ent = decode_map_38[prefix_state][opcode]
			} else if opcode == 0x3A {
				if pos >= len(data) do return 0
				opcode = data[pos]
				pos += 1
				ent = decode_map_3A[prefix_state][opcode]
			} else {
				ent = decode_map_2[prefix_state][opcode]
			}
		case u8(DESC_ESCAPE_38):
			ent = decode_map_38[prefix_state][opcode]
		case u8(DESC_ESCAPE_3A):
			ent = decode_map_3A[prefix_state][opcode]
		}
		desc = u8(ent.desc)
	}

	if desc & u8(DESC_INVALID) != 0 do return 0

	if desc & u8(DESC_IS_PREFIX) != 0 do return 0

	if desc & u8(DESC_HAS_MODRM) != 0 {
		if pos >= len(data) do return 0
		modrm := data[pos]
		pos += 1

		mod := modrm >> 6
		rm := modrm & 7

		addr_size: u8 = 32
		if mode == .Mode_64 {
			addr_size = 32 if has_67 else 64
		} else {
			addr_size = 16 if has_67 else 32
		}

		if addr_size == 16 {
			if mod == 0 && rm == 6 {
				pos += 2
			} else if mod == 1 {
				pos += 1
			} else if mod == 2 {
				pos += 2
			}
		} else {
			sib_byte: u8 = 0
			if mod != 3 && rm == 4 {
				if pos >= len(data) do return 0
				sib_byte = data[pos]
				pos += 1
			}

			if mod == 1 {
				pos += 1
			} else if mod == 2 {
				pos += 4
			} else if mod == 0 {
				if rm == 5 {
					pos += 4
				} else if rm == 4 && (sib_byte & 0x07) == 5 {
					pos += 4
				}
			}
		}
	}

	imm_type := desc & u8(DESC_IMM_MASK)
	imm_size: int = 0

	switch imm_type {
	case u8(IMM_NONE):
		imm_size = 0
	case u8(IMM_IB):
		imm_size = 1
	case u8(IMM_IW):
		imm_size = 2
	case u8(IMM_IV):
		imm_size = 2 if has_66 else 4
	case u8(IMM_IZ):
		imm_size = 2 if has_66 else 4
	case u8(IMM_MOFFS):
		if mode == .Mode_64 {
			imm_size = 4 if has_67 else 8
		} else {
			imm_size = 2 if has_67 else 4
		}
	case u8(IMM_IB_IB):
		imm_size = 2
	case u8(IMM_IW_IB):
		imm_size = 3
	}

	pos += imm_size

	if pos > MAX_INST_LEN || pos > len(data) do return 0
	return pos
}

decode :: proc "contextless" (data: []u8, mode: Mode) -> (inst: Inst, ok: bool) {
	if len(data) == 0 {
		return {}, false
	}

	pos := 0
	prefix_state := 0

	read :: proc "contextless" (data: []u8, pos: ^int) -> (u8, bool) #no_bounds_check {
		if pos^ >= len(data) || pos^ >= MAX_INST_LEN {
			return 0, false
		}
		b := data[pos^]
		pos^ += 1
		return b, true
	}

	peek :: proc "contextless" (data: []u8, pos: int) -> (u8, bool) #no_bounds_check {
		if pos >= len(data) || pos >= MAX_INST_LEN {
			return 0, false
		}
		return data[pos], true
	}

	prefix_loop: for pos < MAX_INST_LEN && pos < len(data) {
		b := data[pos]
		p := prefix_table[b]

		if p & 0xF0 == 0xF0 do break prefix_loop

		switch b {
		case 0xF0:
			inst.prefix_f0 = true
		case 0xF2:
			inst.prefix_f2 = true
			prefix_state = PREFIX_F2
		case 0xF3:
			inst.prefix_f3 = true
			prefix_state = PREFIX_F3
		case 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65:
			inst.prefix_seg = b
		case 0x66:
			inst.prefix_66 = true
			if prefix_state == 0 do prefix_state = PREFIX_66
		case 0x67:
			inst.prefix_67 = true
		}
		pos += 1
	}

	if mode == .Mode_64 {
		b, b_ok := peek(data, pos)
		if !b_ok {
			return {}, false
		}
		if b >= 0x40 && b <= 0x4F {
			inst.rex = b
			pos += 1
		}
	}

	b, b_ok := peek(data, pos)
	if !b_ok {
		return {}, false
	}

	if b == 0xC5 {
		b2, ok2 := peek(data, pos + 1)
		if !ok2 {
			return {}, false
		}
		is_vex := (mode == .Mode_64) || ((b2 & 0xC0) == 0xC0)
		if is_vex {
			pos += 2
			inst.vex[0] = 0xC5
			inst.vex[1] = b2
			inst.encoding = .VEX
		}
	} else if b == 0xC4 {
		b2, ok2 := peek(data, pos + 1)
		if !ok2 {
			return {}, false
		}
		is_vex := (mode == .Mode_64) || ((b2 & 0xC0) == 0xC0)
		if is_vex {
			if pos + 2 >= len(data) {
				return {}, false
			}
			inst.vex[0] = 0xC4
			inst.vex[1] = b2
			inst.vex[2] = data[pos + 2]
			pos += 3
			inst.encoding = .VEX
		}
	} else if b == 0x62 && mode == .Mode_64 {
		if pos + 4 > len(data) {
			return {}, false
		}
		p1 := data[pos + 1]
		if (p1 & 0x0C) == 0 && (p1 & 0x10) == 0 {
			inst.evex[0] = 0x62
			inst.evex[1] = data[pos + 1]
			inst.evex[2] = data[pos + 2]
			inst.evex[3] = data[pos + 3]
			pos += 4
			inst.encoding = .EVEX
		}
	} else if b == 0x8F {
		next, next_ok := peek(data, pos + 1)
		if next_ok && (next & 0x38) != 0 {
			is_xop := (mode == .Mode_64) || ((next & 0xC0) == 0xC0)
			if is_xop {
				if pos + 2 >= len(data) {
					return {}, false
				}
				inst.vex[0] = 0x8F
				inst.vex[1] = next
				inst.vex[2] = data[pos + 2]
				pos += 3
				inst.encoding = .XOP
			}
		}
	}

	inst.rex_w = (inst.rex & 0x08) != 0
	if inst.encoding == .VEX && inst.vex[0] == 0xC4 {
		inst.rex_w = (inst.vex[2] & 0x80) != 0
	} else if inst.encoding == .EVEX {
		inst.rex_w = (inst.evex[2] & 0x80) != 0
	}

	if mode == .Mode_64 {
		inst.operand_size = 64 if inst.rex_w else (16 if inst.prefix_66 else 32)
		inst.address_size = 32 if inst.prefix_67 else 64
	} else {
		inst.operand_size = 16 if inst.prefix_66 else 32
		inst.address_size = 16 if inst.prefix_67 else 32
	}

	opcode_map: u8 = 0

	if inst.encoding == .VEX {
		if inst.vex[0] == 0xC5 {
			opcode_map = 1
			prefix_state = int(inst.vex[1] & 0x03)
		} else {
			opcode_map = inst.vex[1] & 0x1F
			prefix_state = int(inst.vex[2] & 0x03)
		}
		op, op_ok := read(data, &pos)
		if !op_ok {
			return {}, false
		}
		inst.opcode[0] = op
		inst.opcode_len = 1
	} else if inst.encoding == .EVEX {
		opcode_map = inst.evex[1] & 0x03
		prefix_state = int(inst.evex[2] & 0x03)
		op, op_ok := read(data, &pos)
		if !op_ok {
			return {}, false
		}
		inst.opcode[0] = op
		inst.opcode_len = 1
	} else if inst.encoding == .XOP {
		opcode_map = inst.vex[1] & 0x1F
		prefix_state = int(inst.vex[2] & 0x03)
		op, op_ok := read(data, &pos)
		if !op_ok {
			return {}, false
		}
		inst.opcode[0] = op
		inst.opcode_len = 1
	} else {
		op, op_ok := read(data, &pos)
		if !op_ok {
			return {}, false
		}

		if op == 0x9B {
			next, next_ok := peek(data, pos)
			if next_ok && next >= 0xD8 && next <= 0xDF {
				inst.prefix_fwait = true
				op, op_ok = read(data, &pos)
				if !op_ok {
					return {}, false
				}
			}
		}

		inst.opcode[0] = op
		inst.opcode_len = 1

		if op == 0x0F {
			op2, op2_ok := read(data, &pos)
			if !op2_ok {
				return {}, false
			}
			inst.opcode[1] = op2
			inst.opcode_len = 2
			opcode_map = 1

			if op2 == 0x38 {
				op3, op3_ok := read(data, &pos)
				if !op3_ok {
					return {}, false
				}
				inst.opcode[2] = op3
				inst.opcode_len = 3
				opcode_map = 2
			} else if op2 == 0x3A {
				op3, op3_ok := read(data, &pos)
				if !op3_ok {
					return {}, false
				}
				inst.opcode[2] = op3
				inst.opcode_len = 3
				opcode_map = 3
			}
		}
	}

	final_opcode := inst.opcode[inst.opcode_len - 1]

	ent: Opcode_Full
	switch opcode_map {
	case 0:
		ent = decode_map_1[prefix_state][final_opcode]
	case 1:
		ent = decode_map_2[prefix_state][final_opcode]
	case 2:
		ent = decode_map_38[prefix_state][final_opcode]
	case 3:
		ent = decode_map_3A[prefix_state][final_opcode]
	case:
		ent = {DESC_INVALID, .INVALID, .NONE, 0, 0, {}}
	}

	desc := u8(ent.desc)
	inst.mnemonic = ent.mnemonic
	inst.isa = ent.isa

	if desc & u8(DESC_INVALID) != 0 {
		inst.mnemonic = .INVALID
	}

	needs_modrm := (desc & u8(DESC_HAS_MODRM)) != 0

	if inst.encoding == .VEX || inst.encoding == .EVEX || inst.encoding == .XOP {
		needs_modrm = true
	}

	if needs_modrm {
		modrm_byte, modrm_ok := read(data, &pos)
		if !modrm_ok {
			return {}, false
		}
		inst.modrm = modrm_byte
		inst.has_modrm = true

		mod := (modrm_byte >> 6) & 0x03
		rm := modrm_byte & 0x07
		reg := (modrm_byte >> 3) & 0x07

		secondary_handled := false

		if ent.secondary_id != 0 && mod == 0b11 {
			sec_table := secondary_tables[ent.secondary_id]
			if sec_table != nil {
				sec_idx := modrm_byte - 0xC0
				sec_mnem := sec_table[sec_idx]
				if sec_mnem != .INVALID {
					inst.mnemonic = sec_mnem
					secondary_handled = true
				}
			}
		}

		if opcode_map == 1 {
			override := two_byte_overrides[inst.opcode[1]]
			if override != .INVALID {
				inst.mnemonic = override
			}
		}

		if !secondary_handled && ent.group_id != 0 && ent.group_id <= u8(len(group_table_mem)) {
			group_idx := ent.group_id - 1
			group_ent: Group_Desc
			if mod == 0b11 {
				group_ent = group_table_reg[group_idx][reg]
			} else {
				group_ent = group_table_mem[group_idx][reg]
			}
			inst.mnemonic = group_ent.mnemonic
			inst.isa = group_ent.isa
			desc = u8(group_ent.desc)

			if group_ent.variant_id != 0 {
				gv := group_variant_table[group_ent.variant_id]
				inst.mnemonic = apply_group_variant(inst.mnemonic, gv, &inst, mode)
			}
		}

		if mod != 0b11 && rm == 0b100 && inst.address_size != 16 {
			sib_byte, sib_ok := read(data, &pos)
			if !sib_ok {
				return {}, false
			}
			inst.sib = sib_byte
			inst.has_sib = true
		}
		if inst.address_size == 16 {
			switch mod {
			case 0b00:
				if rm == 0b110 {
					inst.disp_size = 2
				}
			case 0b01:
				inst.disp_size = 1
			case 0b10:
				inst.disp_size = 2
			}
		} else {
			switch mod {
			case 0b00:
				if rm == 0b101 {
					inst.disp_size = 4
				} else if inst.has_sib && (inst.sib & 0x07) == 0b101 {
					inst.disp_size = 4
				}
			case 0b01:
				inst.disp_size = 1
			case 0b10:
				inst.disp_size = 4
			}
		}
	}

	if inst.disp_size > 0 {
		if pos + int(inst.disp_size) > len(data) || pos + int(inst.disp_size) > MAX_INST_LEN {
			return {}, false
		}
		pos += int(inst.disp_size)
	}

	imm_type := desc & u8(DESC_IMM_MASK)

	switch imm_type {
	case u8(IMM_NONE):
		inst.imm_size = 0
	case u8(IMM_IB):
		inst.imm_size = 1
	case u8(IMM_IW):
		inst.imm_size = 2
	case u8(IMM_IV):
		if mode == .Mode_64 && inst.rex_w {
			inst.imm_size = 8
		} else {
			inst.imm_size = u8(inst.operand_size / 8)
		}
	case u8(IMM_IZ):
		if inst.operand_size >= 32 {
			inst.imm_size = 4
		} else {
			inst.imm_size = 2
		}
	case u8(IMM_MOFFS):
		inst.imm_size = u8(inst.address_size / 8)
	case u8(IMM_IB_IB):
		inst.imm_size = 1
		inst.imm2_size = 1
	case u8(IMM_IW_IB):
		inst.imm_size = 2
		inst.imm2_size = 1
	}

	if inst.encoding == .VEX || inst.encoding == .EVEX || inst.encoding == .XOP {
		inst.imm_size = get_vex_imm_size(&inst)
		inst.imm2_size = 0
	}

	if inst.imm_size > 0 {
		if pos + int(inst.imm_size) > len(data) || pos + int(inst.imm_size) > MAX_INST_LEN {
			return {}, false
		}
		pos += int(inst.imm_size)
	}

	if inst.imm2_size > 0 {
		if pos + int(inst.imm2_size) > len(data) || pos + int(inst.imm2_size) > MAX_INST_LEN {
			return {}, false
		}
		pos += int(inst.imm2_size)
	}

	if pos > MAX_INST_LEN {
		return {}, false
	}

	inst.mnemonic = select_mnemonic_variant(
		inst.mnemonic,
		&inst,
		mode,
		opcode_map,
		u8(prefix_state),
	)

	inst.length = u8(pos)
	return inst, true
}

@(private = "file")
select_mnemonic_variant :: proc "contextless" (
	base_mnemonic: Mnemonic,
	inst: ^Inst,
	mode: Mode,
	opcode_map: u8,
	prefix_state: u8,
) -> Mnemonic {
	mnemonic := base_mnemonic
	final_opcode := inst.opcode[inst.opcode_len - 1]

	if variant := find_mnemonic_variant(opcode_map, prefix_state, final_opcode); variant != nil {
		switch variant.handler_type {
		case .Simple:

		case .Opsize_16_32_64:
			switch inst.operand_size {
			case 16:
				mnemonic = variant.variants[0]
			case 32:
				mnemonic = variant.variants[1]
			case 64:
				mnemonic = variant.variants[2]
			}

		case .Mode32_64:
			mnemonic = variant.variants[mode == .Mode_64 ? 1 : 0]

		case .RexW:
			mnemonic = variant.variants[inst.rex_w ? 1 : 0]

		case .Mod_Mem_Reg:
			mod := (inst.modrm >> 6) & 0x03
			mnemonic = variant.variants[mod == 0b11 ? 1 : 0]

		case .Fwait:
			mnemonic = variant.variants[inst.prefix_fwait ? 1 : 0]
		}

		if mnemonic != .INVALID {
			return mnemonic
		}
		mnemonic = base_mnemonic
	}

	for &pair in fpu_fwait_variants {
		if inst.prefix_fwait {
			if mnemonic == pair[0] {
				return pair[1]
			}
		} else {
			if mnemonic == pair[1] {
				return pair[0]
			}
		}
	}

	return mnemonic
}

@(private = "file")
apply_group_variant :: proc "contextless" (
	base_mnemonic: Mnemonic,
	gv: Group_Variant,
	inst: ^Inst,
	mode: Mode,
) -> Mnemonic {
	switch gv.handler_type {
	case .Simple:
		return base_mnemonic
	case .RexW:
		return gv.variants[inst.rex_w ? 1 : 0]
	case .Mode32_64:
		return gv.variants[mode == .Mode_64 ? 1 : 0]
	case .Opsize_16_32_64:
		if inst.operand_size == 64 {
			return gv.variants[1]
		}
		return gv.variants[0]
	case .Mod_Mem_Reg:
		mod := (inst.modrm >> 6) & 0x03
		return gv.variants[mod == 0b11 ? 1 : 0]
	case .Fwait:
		return gv.variants[inst.prefix_fwait ? 1 : 0]
	}
	return base_mnemonic
}

@(private = "file")
get_vex_imm_size :: proc "contextless" (inst: ^Inst) -> u8 {
	pp: u8
	if inst.encoding == .VEX {
		if inst.vex[0] == 0xC5 {
			pp = inst.vex[1] & 0x03
		} else {
			pp = inst.vex[2] & 0x03
		}
	} else if inst.encoding == .EVEX {
		pp = inst.evex[2] & 0x03
	} else {
		pp = inst.vex[2] & 0x03
	}

	map_sel: u8
	if inst.encoding == .VEX {
		if inst.vex[0] == 0xC5 {
			map_sel = 1
		} else {
			map_sel = inst.vex[1] & 0x1F
		}
	} else if inst.encoding == .EVEX {
		map_sel = inst.evex[1] & 0x03
	} else {
		map_sel = inst.vex[1] & 0x1F
	}

	if map_sel == 3 {
		return 1
	}

	opcode := inst.opcode[0]
	switch opcode {
	case 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F:
		return 1
	case 0x14, 0x15, 0x16, 0x17:
		return 1
	case 0x20, 0x21, 0x22:
		return 1
	case 0x40, 0x41, 0x42, 0x44:
		return 1
	case 0x4A, 0x4B, 0x4C:
		return 1
	case 0x60, 0x61, 0x62, 0x63:
		return 1
	case 0xC2:
		return 1
	case 0xC4, 0xC5, 0xC6:
		return 1
	}

	_ = pp
	return 0
}
