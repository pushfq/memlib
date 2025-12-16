package build_support

import "core:encoding/xml"
import "core:fmt"
import "core:os"
import "core:slice"
import "core:strings"
import "core:unicode"

INVARIANT_CONTENT :: string(#load("x86-invariant.odin.txt"))

DESC_INVALID :: u8(0x80)
DESC_HAS_MODRM :: u8(0x40)
DESC_IS_PREFIX :: u8(0x20)
DESC_ESCAPE_0F :: u8(0x08)
DESC_ESCAPE_38 :: u8(0x10)
DESC_ESCAPE_3A :: u8(0x18)
DESC_ESCAPE_MASK :: u8(0x18)
DESC_IMM_MASK :: u8(0x07)

IMM_NONE :: u8(0)
IMM_IB :: u8(1)
IMM_IW :: u8(2)
IMM_IV :: u8(3)
IMM_IZ :: u8(4)
IMM_MOFFS :: u8(5)
IMM_IB_IB :: u8(6)
IMM_IW_IB :: u8(7)

PREFIX_NP :: 0
PREFIX_F3 :: 1
PREFIX_F2 :: 2
PREFIX_66 :: 3

ISA_Ext :: enum u8 {
	NONE = 0,
	I386,
	I486,
	I586,
	I686,
	MMX,
	SSE1,
	SSE2,
	SSE3,
	SSSE3,
	SSE41,
	SSE42,
	LZCNT,
	BMI1,
	VMX,
	SMX,
}

Parsed_Entry :: struct {
	opcode:       u8,
	opcode_ext:   i8,
	sec_opcode:   u8,
	is_3byte:     bool,
	is_3byte_38:  bool,
	is_3byte_3A:  bool,
	mnemonic:     string,
	has_modrm:    bool,
	is_prefix:    bool,
	invalid_64:   bool,
	lock_allowed: bool,
	prefix_req:   string,
	imm_type:     Imm_Type,
	has_moffs:    bool,
	plus_r:       bool,
	isa_ext:      ISA_Ext,
	mod_mem_only: bool,
	mod_reg_only: bool,
}

Imm_Type :: enum u8 {
	None,
	Ib,
	Iw,
	Iv,
	Iz,
	Ap,
	Ib_Ib,
	Iw_Ib,
}

Flat_Entry :: struct {
	desc:         u8,
	mnemonic:     Mnemonic,
	isa:          ISA_Ext,
	group_id:     u8,
	secondary_id: u8,
}

Mnemonic :: distinct u16
MNEMONIC_INVALID :: Mnemonic(0)

Generator :: struct {
	mnemonics:        map[string]bool,
	mnemonic_list:    [dynamic]string,
	one_byte:         [dynamic]Parsed_Entry,
	two_byte:         [dynamic]Parsed_Entry,
	three_byte_38:    [dynamic]Parsed_Entry,
	three_byte_3A:    [dynamic]Parsed_Entry,
	doc:              ^xml.Document,
	map_1:            [4][256]Flat_Entry,
	map_2:            [4][256]Flat_Entry,
	map_38:           [4][256]Flat_Entry,
	map_3A:           [4][256]Flat_Entry,
	next_group_id:    u8,
	group_entries:    [dynamic]Group_Data,
	fpu_reg_tables:   [8][64]FPU_Entry,
	variants:         [dynamic]Variant_Data,
	secondary_tables: [dynamic]Secondary_Table,
	group_variants:   [dynamic]Group_Variant_Data,
}

Variant_Handler :: enum u8 {
	Simple = 0,
	Opsize_16_32_64,
	Mode32_64,
	RexW,
	Mod_Mem_Reg,
	Fwait,
}

Variant_Data :: struct {
	opcode_map:   u8,
	prefix_state: int,
	opcode:       u8,
	handler:      Variant_Handler,
	variants:     [3]string,
}

Group_Data :: struct {
	table:         int,
	opcode:        u8,
	prefix:        int,
	mem:           [8]Group_Entry,
	reg:           [8]Group_Entry,
	has_mod_split: bool,
}

Group_Entry :: struct {
	desc:       u8,
	mnemonic:   Mnemonic,
	isa:        ISA_Ext,
	variant_id: u8,
}

FPU_Entry :: struct {
	mnemonic: Mnemonic,
	isa:      ISA_Ext,
}

Secondary_Table :: struct {
	name:    string,
	entries: [64]Mnemonic,
}

Group_Variant_Data :: struct {
	handler:  Variant_Handler,
	variants: [2]string,
}

main :: proc() {
	args := os.args
	if len(args) < 2 {
		fmt.eprintln("Usage: gen <x86reference.xml>")
		os.exit(1)
	}

	xml_path := args[1]
	gen: Generator
	gen.mnemonics = make(map[string]bool)

	doc, err := xml.load_from_file(xml_path)
	if err != .None {
		fmt.eprintfln("Error loading XML: %v", err)
		os.exit(1)
	}
	defer xml.destroy(doc)
	gen.doc = doc

	fmt.printfln("Parsing %s...", xml_path)

	if len(doc.elements) == 0 {
		fmt.eprintln("No elements in XML document")
		os.exit(1)
	}

	root := doc.elements[0]

	for v in root.value {
		child_id, is_elem := v.(xml.Element_ID)
		if !is_elem do continue

		child := doc.elements[child_id]
		if child.kind != .Element do continue

		switch child.ident {
		case "one-byte":
			parse_opcode_section(&gen, child_id, false)
		case "two-byte":
			parse_opcode_section(&gen, child_id, true)
		}
	}

	build_variant_tables(&gen)

	for mnem in gen.mnemonics {
		append(&gen.mnemonic_list, mnem)
	}
	slice.sort(gen.mnemonic_list[:])

	fmt.printfln("Found %d unique mnemonics", len(gen.mnemonic_list))
	fmt.printfln("One-byte entries: %d", len(gen.one_byte))
	fmt.printfln("Two-byte entries: %d", len(gen.two_byte))
	fmt.printfln("Three-byte 0F38 entries: %d", len(gen.three_byte_38))
	fmt.printfln("Three-byte 0F3A entries: %d", len(gen.three_byte_3A))

	build_flattened_tables(&gen)

	fmt.printfln("Groups: %d", len(gen.group_entries))

	generate_output(&gen, "../ml-x86-autogen.odin")
	fmt.println("Done!")
}

parse_opcode_section :: proc(gen: ^Generator, section_id: xml.Element_ID, is_two_byte: bool) {
	doc := gen.doc
	section := doc.elements[section_id]

	for v in section.value {
		child_id, is_elem := v.(xml.Element_ID)
		if !is_elem do continue

		child := doc.elements[child_id]
		if child.kind != .Element do continue

		if child.ident == "pri_opcd" {
			opcode_str := get_attr(child, "value")
			opcode := parse_hex(opcode_str)
			parse_opcode_entries(gen, child_id, opcode, is_two_byte)
		}
	}
}

parse_opcode_entries :: proc(
	gen: ^Generator,
	opcd_id: xml.Element_ID,
	opcode: u8,
	is_two_byte: bool,
) {
	doc := gen.doc
	opcd_elem := doc.elements[opcd_id]

	for v in opcd_elem.value {
		child_id, is_elem := v.(xml.Element_ID)
		if !is_elem do continue

		child := doc.elements[child_id]
		if child.kind != .Element do continue

		if child.ident == "entry" {
			entry := parse_entry(gen, child_id, opcode, is_two_byte)
			if entry.mnemonic != "" {
				if entry.is_3byte_38 {
					append(&gen.three_byte_38, entry)
				} else if entry.is_3byte_3A {
					append(&gen.three_byte_3A, entry)
				} else if is_two_byte {
					append(&gen.two_byte, entry)
				} else {
					append(&gen.one_byte, entry)
				}
			}
		}
	}
}

parse_entry :: proc(
	gen: ^Generator,
	entry_id: xml.Element_ID,
	opcode: u8,
	is_two_byte: bool,
) -> Parsed_Entry {
	doc := gen.doc
	entry_elem := doc.elements[entry_id]

	result := Parsed_Entry {
		opcode     = opcode,
		opcode_ext = -1,
	}

	result.has_modrm = get_attr(entry_elem, "r") == "yes"
	result.lock_allowed = get_attr(entry_elem, "lock") == "yes"

	mode := get_attr(entry_elem, "mode")
	attr := get_attr(entry_elem, "attr")

	if mode == "e" && attr == "invd" {
		result.invalid_64 = true
	}

	mod := get_attr(entry_elem, "mod")
	switch mod {
	case "mem", "!11":
		result.mod_mem_only = true
	case "nomem", "11", "reg":
		result.mod_reg_only = true
	}

	for v in entry_elem.value {
		child_id, is_elem := v.(xml.Element_ID)
		if !is_elem do continue

		child := doc.elements[child_id]
		if child.kind != .Element do continue

		switch child.ident {
		case "opcd_ext":
			ext_str := get_element_text(doc, child_id)
			if ext_str != "" {
				result.opcode_ext = i8(parse_hex(ext_str))
				result.has_modrm = true
			}

		case "sec_opcd":
			sec_str := get_element_text(doc, child_id)
			escape := get_attr(child, "escape")
			if sec_str != "" {
				result.sec_opcode = parse_hex(sec_str)
				if escape == "yes" && is_two_byte {
					result.is_3byte = true
					if opcode == 0x38 {
						result.is_3byte_38 = true
						result.opcode = result.sec_opcode
					} else if opcode == 0x3A {
						result.is_3byte_3A = true
						result.opcode = result.sec_opcode
					}
				}
			}

		case "pref":
			result.prefix_req = get_element_text(doc, child_id)

		case "syntax":
			parse_syntax(gen, child_id, &result)

		case "grp1":
			grp := get_element_text(doc, child_id)
			if grp == "prefix" {
				result.is_prefix = true
			}

		case "instr_ext":
			ext := get_element_text(doc, child_id)
			switch ext {
			case "mmx":
				result.isa_ext = .MMX
			case "sse1":
				result.isa_ext = .SSE1
			case "sse2":
				result.isa_ext = .SSE2
			case "sse3":
				result.isa_ext = .SSE3
			case "ssse3":
				result.isa_ext = .SSSE3
			case "sse41":
				result.isa_ext = .SSE41
			case "sse42":
				result.isa_ext = .SSE42
			case "bmi1":
				result.isa_ext = .BMI1
			case "lzcnt":
				result.isa_ext = .LZCNT
			case "vmx":
				result.isa_ext = .VMX
			case "smx":
				result.isa_ext = .SMX
			}

		case "proc_start":
			proc_ver := get_element_text(doc, child_id)
			switch proc_ver {
			case "03":
				if result.isa_ext == .NONE do result.isa_ext = .I386
			case "04":
				if result.isa_ext == .NONE do result.isa_ext = .I486
			case "05":
				if result.isa_ext == .NONE do result.isa_ext = .I586
			case "06":
				if result.isa_ext == .NONE do result.isa_ext = .I686
			}
		}
	}

	return result
}

parse_syntax :: proc(gen: ^Generator, syntax_id: xml.Element_ID, result: ^Parsed_Entry) {
	doc := gen.doc
	syntax_elem := doc.elements[syntax_id]

	imm_sizes: [2]u8
	imm_count := 0

	for v in syntax_elem.value {
		child_id, is_elem := v.(xml.Element_ID)
		if !is_elem do continue

		child := doc.elements[child_id]
		if child.kind != .Element do continue

		switch child.ident {
		case "mnem":
			mnem := get_element_text(doc, child_id)
			if mnem != "" {
				result.mnemonic = mnem
				gen.mnemonics[mnem] = true
			}

		case "src", "dst":
			addr_mode: string
			op_type: string

			for sv in child.value {
				sub_id, is_sub := sv.(xml.Element_ID)
				if !is_sub do continue

				sub := doc.elements[sub_id]
				if sub.kind != .Element do continue

				switch sub.ident {
				case "a":
					addr_mode = get_element_text(doc, sub_id)
				case "t":
					op_type = get_element_text(doc, sub_id)
				}
			}

			if addr_mode == "Z" do result.plus_r = true
			if addr_mode == "O" do result.has_moffs = true

			switch addr_mode {
			case "E",
			     "G",
			     "M",
			     "R",
			     "C",
			     "D",
			     "S",
			     "T",
			     "V",
			     "W",
			     "N",
			     "P",
			     "Q",
			     "U",
			     "H",
			     "L",
			     "B":
				result.has_modrm = true
			}

			if imm_count < 2 {
				switch addr_mode {
				case "I":
					switch op_type {
					case "b", "bs", "bss":
						imm_sizes[imm_count] = 1; imm_count += 1
					case "w":
						imm_sizes[imm_count] = 2; imm_count += 1
					case "v", "vqp":
						imm_sizes[imm_count] = 0xFF; imm_count += 1
					case "z", "vds", "vs":
						imm_sizes[imm_count] = 0xFE; imm_count += 1
					case "d":
						imm_sizes[imm_count] = 4; imm_count += 1
					}
				case "J":
					switch op_type {
					case "b", "bs":
						imm_sizes[imm_count] = 1; imm_count += 1
					case "v", "vds", "z":
						imm_sizes[imm_count] = 0xFE; imm_count += 1
					}
				case "A":
					switch op_type {
					case "p":
						imm_sizes[imm_count] = 0xFD; imm_count += 1
					}
				}
			}
		}
	}

	if imm_count == 1 {
		switch imm_sizes[0] {
		case 1:
			result.imm_type = .Ib
		case 2:
			result.imm_type = .Iw
		case 0xFF:
			result.imm_type = .Iv
		case 0xFE:
			result.imm_type = .Iz
		case 0xFD:
			result.imm_type = .Ap
		}
	} else if imm_count == 2 {
		if imm_sizes[0] == 2 && imm_sizes[1] == 1 {
			result.imm_type = .Iw_Ib
		} else if imm_sizes[0] == 1 && imm_sizes[1] == 1 {
			result.imm_type = .Ib_Ib
		}
	}
}

get_attr :: proc(elem: xml.Element, name: string) -> string {
	for attr in elem.attribs {
		if attr.key == name do return attr.val
	}
	return ""
}

get_element_text :: proc(doc: ^xml.Document, elem_id: xml.Element_ID) -> string {
	elem := doc.elements[elem_id]
	for v in elem.value {
		text, is_str := v.(string)
		if is_str do return strings.trim_space(text)
	}
	return ""
}

parse_hex :: proc(s: string) -> u8 {
	if len(s) == 0 do return 0
	result: u8 = 0
	for c in s {
		result *= 16
		switch c {
		case '0' ..= '9':
			result += u8(c - '0')
		case 'A' ..= 'F':
			result += u8(c - 'A' + 10)
		case 'a' ..= 'f':
			result += u8(c - 'a' + 10)
		}
	}
	return result
}

prefix_to_state :: proc(prefix: string) -> int {
	switch prefix {
	case "F3":
		return PREFIX_F3
	case "F2":
		return PREFIX_F2
	case "66":
		return PREFIX_66
	}
	return PREFIX_NP
}

imm_type_to_desc :: proc(imm: Imm_Type) -> u8 {
	switch imm {
	case .None:
		return IMM_NONE
	case .Ib:
		return IMM_IB
	case .Iw:
		return IMM_IW
	case .Iv:
		return IMM_IV
	case .Iz:
		return IMM_IZ
	case .Ap:
		return IMM_IV
	case .Ib_Ib:
		return IMM_IB_IB
	case .Iw_Ib:
		return IMM_IW_IB
	}
	return IMM_NONE
}

string_to_mnemonic :: proc(mnem: string, gen: ^Generator) -> Mnemonic {
	for m, i in gen.mnemonic_list {
		if m == mnem do return Mnemonic(i + 1)
	}
	return MNEMONIC_INVALID
}

mnemonic_to_ident :: proc(mnem: string) -> string {
	sb := strings.builder_make()
	for c in mnem {
		if unicode.is_alpha(c) || unicode.is_digit(c) || c == '_' {
			strings.write_rune(&sb, c)
		} else {
			strings.write_rune(&sb, '_')
		}
	}
	return strings.to_string(sb)
}

isa_ext_string :: proc(isa: ISA_Ext) -> string {
	switch isa {
	case .NONE:
		return "NONE"
	case .I386:
		return "I386"
	case .I486:
		return "I486"
	case .I586:
		return "I586"
	case .I686:
		return "I686"
	case .MMX:
		return "MMX"
	case .SSE1:
		return "SSE1"
	case .SSE2:
		return "SSE2"
	case .SSE3:
		return "SSE3"
	case .SSSE3:
		return "SSSE3"
	case .SSE41:
		return "SSE41"
	case .SSE42:
		return "SSE42"
	case .LZCNT:
		return "LZCNT"
	case .BMI1:
		return "BMI1"
	case .VMX:
		return "VMX"
	case .SMX:
		return "SMX"
	}
	return "NONE"
}

variant_handler_str :: proc(h: Variant_Handler) -> string {
	switch h {
	case .Simple:
		return "Simple"
	case .Opsize_16_32_64:
		return "Opsize_16_32_64"
	case .Mode32_64:
		return "Mode32_64"
	case .RexW:
		return "RexW"
	case .Mod_Mem_Reg:
		return "Mod_Mem_Reg"
	case .Fwait:
		return "Fwait"
	}
	return "Simple"
}

build_flattened_tables :: proc(gen: ^Generator) {
	for p in 0 ..< 4 {
		for o in 0 ..< 256 {
			gen.map_1[p][o] = {
				desc = DESC_INVALID,
			}
			gen.map_2[p][o] = {
				desc = DESC_INVALID,
			}
			gen.map_38[p][o] = {
				desc = DESC_INVALID,
			}
			gen.map_3A[p][o] = {
				desc = DESC_INVALID,
			}
		}
	}

	prefixes := []u8{0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
	for p in 0 ..< 4 {
		for pref in prefixes {
			gen.map_1[p][pref] = {
				desc = DESC_IS_PREFIX,
			}
		}
	}

	for p in 0 ..< 4 {
		gen.map_1[p][0x0F] = {
			desc = DESC_ESCAPE_0F,
		}
		gen.map_2[p][0x38] = {
			desc = DESC_ESCAPE_38,
		}
		gen.map_2[p][0x3A] = {
			desc = DESC_ESCAPE_3A,
		}
	}

	for p in 0 ..< 4 {
		for i in u8(0xD8) ..= 0xDF {
			gen.map_1[p][i] = {
				desc         = DESC_HAS_MODRM,
				secondary_id = i - 0xD8 + 1,
			}
		}
	}

	for p in 0 ..< 4 {
		gen.map_1[p][0xC4] = {
			desc = DESC_INVALID,
		}
		gen.map_1[p][0xC5] = {
			desc = DESC_INVALID,
		}
	}

	for p in 0 ..< 4 {
		gen.map_1[p][0xD4] = {
			desc     = IMM_IB,
			mnemonic = string_to_mnemonic("AAM", gen),
		}
		gen.map_1[p][0xD5] = {
			desc     = IMM_IB,
			mnemonic = string_to_mnemonic("AAD", gen),
		}
	}

	for pass in 0 ..< 2 {
		for &entry in gen.one_byte {
			if entry.mnemonic == "" do continue
			if entry.is_prefix do continue
			if entry.opcode == 0x0F do continue

			has_prefix_req := entry.prefix_req != ""

			if pass == 0 && !has_prefix_req do continue
			if pass == 1 && has_prefix_req do continue

			if entry.opcode_ext >= 0 {
				process_group_entry(gen, &entry, 0)
				continue
			}

			prefix_state := prefix_to_state(entry.prefix_req)

			desc: u8 = 0
			if entry.has_modrm do desc |= DESC_HAS_MODRM
			if entry.has_moffs {
				desc |= imm_type_to_desc(.None)
				desc |= IMM_MOFFS
			} else {
				desc |= imm_type_to_desc(entry.imm_type)
			}

			mnem := string_to_mnemonic(entry.mnemonic, gen)
			flat := Flat_Entry {
				desc     = desc,
				mnemonic = mnem,
				isa      = entry.isa_ext,
			}

			if entry.plus_r {
				base := entry.opcode & 0xF8
				for i in u8(0) ..< 8 {
					idx := base | i
					place_entry(gen, 0, prefix_state, idx, flat, has_prefix_req)
				}
			} else {
				place_entry(gen, 0, prefix_state, entry.opcode, flat, has_prefix_req)
			}
		}
	}

	for pass in 0 ..< 2 {
		for &entry in gen.two_byte {
			if entry.mnemonic == "" do continue
			if entry.is_3byte do continue

			has_prefix_req := entry.prefix_req != ""
			if pass == 0 && !has_prefix_req do continue
			if pass == 1 && has_prefix_req do continue

			if entry.opcode_ext >= 0 {
				process_group_entry(gen, &entry, 1)
				continue
			}

			prefix_state := prefix_to_state(entry.prefix_req)

			desc: u8 = 0
			if entry.has_modrm do desc |= DESC_HAS_MODRM
			desc |= imm_type_to_desc(entry.imm_type)

			mnem := string_to_mnemonic(entry.mnemonic, gen)
			flat := Flat_Entry {
				desc     = desc,
				mnemonic = mnem,
				isa      = entry.isa_ext,
			}

			if entry.plus_r {
				base := entry.opcode & 0xF8
				for i in u8(0) ..< 8 {
					idx := base | i
					place_entry(gen, 1, prefix_state, idx, flat, has_prefix_req)
				}
			} else {
				place_entry(gen, 1, prefix_state, entry.opcode, flat, has_prefix_req)
			}
		}
	}

	for pass in 0 ..< 2 {
		for &entry in gen.three_byte_38 {
			if entry.mnemonic == "" do continue

			has_prefix_req := entry.prefix_req != ""
			if pass == 0 && !has_prefix_req do continue
			if pass == 1 && has_prefix_req do continue

			prefix_state := prefix_to_state(entry.prefix_req)

			desc: u8 = DESC_HAS_MODRM
			desc |= imm_type_to_desc(entry.imm_type)

			mnem := string_to_mnemonic(entry.mnemonic, gen)
			flat := Flat_Entry {
				desc     = desc,
				mnemonic = mnem,
				isa      = entry.isa_ext,
			}

			place_entry(gen, 2, prefix_state, entry.opcode, flat, has_prefix_req)
		}
	}

	for pass in 0 ..< 2 {
		for &entry in gen.three_byte_3A {
			if entry.mnemonic == "" do continue

			has_prefix_req := entry.prefix_req != ""
			if pass == 0 && !has_prefix_req do continue
			if pass == 1 && has_prefix_req do continue

			prefix_state := prefix_to_state(entry.prefix_req)

			desc: u8 = DESC_HAS_MODRM | IMM_IB
			mnem := string_to_mnemonic(entry.mnemonic, gen)
			flat := Flat_Entry {
				desc     = desc,
				mnemonic = mnem,
				isa      = entry.isa_ext,
			}

			place_entry(gen, 3, prefix_state, entry.opcode, flat, has_prefix_req)
		}
	}

	finalize_groups(gen)
}

place_entry :: proc(
	gen: ^Generator,
	table: int,
	prefix_state: int,
	opcode: u8,
	entry: Flat_Entry,
	has_prefix_req: bool,
) {
	map_ptr: ^[4][256]Flat_Entry
	switch table {
	case 0:
		map_ptr = &gen.map_1
	case 1:
		map_ptr = &gen.map_2
	case 2:
		map_ptr = &gen.map_38
	case 3:
		map_ptr = &gen.map_3A
	case:
		return
	}

	is_reserved :: proc(e: ^Flat_Entry) -> bool {
		if e.desc & DESC_ESCAPE_MASK != 0 do return true
		if e.desc & DESC_IS_PREFIX != 0 do return true
		if e.mnemonic != MNEMONIC_INVALID do return true
		return false
	}

	existing := &map_ptr[prefix_state][opcode]

	if has_prefix_req {
		if !is_reserved(existing) {
			existing^ = entry
		}
	} else {
		if prefix_state == PREFIX_NP {
			if !is_reserved(existing) {
				existing^ = entry
			}
			for p in 1 ..< 4 {
				other := &map_ptr[p][opcode]
				if !is_reserved(other) {
					other^ = entry
				}
			}
		}
	}
}

process_group_entry :: proc(gen: ^Generator, entry: ^Parsed_Entry, table: int) {
	if table == 0 && entry.opcode >= 0xD8 && entry.opcode <= 0xDF && entry.sec_opcode >= 0xC0 {
		fpu_idx := entry.opcode - 0xD8
		sec_idx := entry.sec_opcode - 0xC0
		mnem := string_to_mnemonic(entry.mnemonic, gen)
		gen.fpu_reg_tables[fpu_idx][sec_idx] = FPU_Entry {
			mnemonic = mnem,
			isa      = entry.isa_ext,
		}
		return
	}

	prefix_state := prefix_to_state(entry.prefix_req)

	found_idx := -1
	for &g, i in gen.group_entries {
		if g.table == table && g.opcode == entry.opcode && g.prefix == prefix_state {
			found_idx = i
			break
		}
	}

	if found_idx < 0 {
		append(
			&gen.group_entries,
			Group_Data{table = table, opcode = entry.opcode, prefix = prefix_state},
		)
		found_idx = len(gen.group_entries) - 1
	}

	group := &gen.group_entries[found_idx]

	desc: u8 = 0
	if entry.has_modrm do desc |= DESC_HAS_MODRM
	desc |= imm_type_to_desc(entry.imm_type)

	mnem := string_to_mnemonic(entry.mnemonic, gen)
	gent := Group_Entry {
		desc     = desc,
		mnemonic = mnem,
		isa      = entry.isa_ext,
	}

	ext := entry.opcode_ext
	if ext >= 0 && ext < 8 {
		if entry.mod_mem_only {
			group.mem[ext] = gent
			group.has_mod_split = true
		} else if entry.mod_reg_only {
			group.reg[ext] = gent
			group.has_mod_split = true
		} else {
			if group.mem[ext].mnemonic == MNEMONIC_INVALID {
				group.mem[ext] = gent
			}
			if group.reg[ext].mnemonic == MNEMONIC_INVALID {
				group.reg[ext] = gent
			}
		}
	}
}

finalize_groups :: proc(gen: ^Generator) {
	for &group, i in gen.group_entries {
		group_id := u8(i + 1)

		map_ptr: ^[4][256]Flat_Entry
		switch group.table {
		case 0:
			map_ptr = &gen.map_1
		case 1:
			map_ptr = &gen.map_2
		case:
			continue
		}

		imm_type: u8 = 0
		for ext in 0 ..< 8 {
			if group.mem[ext].mnemonic != MNEMONIC_INVALID {
				imm_type = group.mem[ext].desc & DESC_IMM_MASK
				break
			}
			if group.reg[ext].mnemonic != MNEMONIC_INVALID {
				imm_type = group.reg[ext].desc & DESC_IMM_MASK
				break
			}
		}

		existing := &map_ptr[group.prefix][group.opcode]
		existing.desc = DESC_HAS_MODRM | imm_type
		existing.group_id = group_id

		if group.prefix == PREFIX_NP {
			for p in 1 ..< 4 {
				other := &map_ptr[p][group.opcode]
				if other.desc & DESC_INVALID != 0 || other.group_id == 0 {
					other.desc = DESC_HAS_MODRM | imm_type
					other.group_id = group_id
				}
			}
		}
	}

	for p in 0 ..< 4 {
		gen.map_2[p][0x01].secondary_id = 9
	}

	assign_group_variant(gen, 1, 0xC7, PREFIX_NP, 1, .RexW, "CMPXCHG8B", "CMPXCHG16B")
}

assign_group_variant :: proc(
	gen: ^Generator,
	table: int,
	opcode: u8,
	prefix: int,
	reg: int,
	handler: Variant_Handler,
	mnem1: string,
	mnem2: string,
) {
	for &group in gen.group_entries {
		if group.table == table && group.opcode == opcode && group.prefix == prefix {
			append(
				&gen.group_variants,
				Group_Variant_Data{handler = handler, variants = {mnem1, mnem2}},
			)
			variant_id := u8(len(gen.group_variants))

			group.mem[reg].variant_id = variant_id
			group.reg[reg].variant_id = variant_id
			return
		}
	}
	fmt.eprintfln(
		"Warning: Could not find group for variant assignment: table=%d opcode=%02X prefix=%d",
		table,
		opcode,
		prefix,
	)
}

build_variant_tables :: proc(gen: ^Generator) {
	add_variant(gen, 0, PREFIX_NP, 0x63, .Mode32_64, "ARPL", "MOVSXD", "")
	add_variant(gen, 0, PREFIX_NP, 0x98, .Opsize_16_32_64, "CBW", "CWDE", "CDQE")
	add_variant(gen, 0, PREFIX_NP, 0x99, .Opsize_16_32_64, "CWD", "CDQ", "CQO")

	for ps in ([]int{PREFIX_NP, PREFIX_F3, PREFIX_F2}) {
		add_variant(gen, 0, ps, 0xA5, .Opsize_16_32_64, "MOVSW", "MOVSD", "MOVSQ")
	}

	for ps in ([]int{PREFIX_NP, PREFIX_F3, PREFIX_F2}) {
		add_variant(gen, 0, ps, 0xA7, .Opsize_16_32_64, "CMPSW", "CMPSD", "CMPSQ")
	}

	for ps in ([]int{PREFIX_NP, PREFIX_F3, PREFIX_F2}) {
		add_variant(gen, 0, ps, 0xAB, .Opsize_16_32_64, "STOSW", "STOSD", "STOSQ")
	}

	for ps in ([]int{PREFIX_NP, PREFIX_F3, PREFIX_F2}) {
		add_variant(gen, 0, ps, 0xAD, .Opsize_16_32_64, "LODSW", "LODSD", "LODSQ")
	}

	for ps in ([]int{PREFIX_NP, PREFIX_F3, PREFIX_F2}) {
		add_variant(gen, 0, ps, 0xAF, .Opsize_16_32_64, "SCASW", "SCASD", "SCASQ")
	}

	for ps in ([]int{PREFIX_NP, PREFIX_F3}) {
		add_variant(gen, 0, ps, 0x6D, .Opsize_16_32_64, "INSW", "INSD", "INSD")
	}

	for ps in ([]int{PREFIX_NP, PREFIX_F3}) {
		add_variant(gen, 0, ps, 0x6F, .Opsize_16_32_64, "OUTSW", "OUTSD", "OUTSD")
	}

	add_variant(gen, 1, PREFIX_NP, 0x12, .Mod_Mem_Reg, "MOVLPS", "MOVHLPS", "")
	add_variant(gen, 1, PREFIX_NP, 0x16, .Mod_Mem_Reg, "MOVHPS", "MOVLHPS", "")

	for v in gen.variants {
		for mnem in v.variants {
			if mnem != "" {
				gen.mnemonics[mnem] = true
			}
		}
	}

	fwait_mnems := []string {
		"FNSAVE",
		"FSAVE",
		"FNSTCW",
		"FSTCW",
		"FNSTENV",
		"FSTENV",
		"FNSTSW",
		"FSTSW",
		"FNCLEX",
		"FCLEX",
		"FNINIT",
		"FINIT",
	}
	for mnem in fwait_mnems {
		gen.mnemonics[mnem] = true
	}

	secondary_0f01_mnems := []string {
		"VMCALL",
		"VMLAUNCH",
		"VMRESUME",
		"VMXOFF",
		"MONITOR",
		"MWAIT",
		"XGETBV",
		"XSETBV",
		"SWAPGS",
		"RDTSCP",
	}
	for mnem in secondary_0f01_mnems {
		gen.mnemonics[mnem] = true
	}

	gen.mnemonics["SYSCALL"] = true
	gen.mnemonics["SYSRET"] = true
}

add_variant :: proc(
	gen: ^Generator,
	opcode_map: u8,
	prefix_state: int,
	opcode: u8,
	handler: Variant_Handler,
	mnem1, mnem2, mnem3: string,
) {
	append(
		&gen.variants,
		Variant_Data {
			opcode_map = opcode_map,
			prefix_state = prefix_state,
			opcode = opcode,
			handler = handler,
			variants = {mnem1, mnem2, mnem3},
		},
	)
}

generate_output :: proc(gen: ^Generator, output_path: string) {
	sb := strings.builder_make()
	defer strings.builder_destroy(&sb)

	strings.write_string(&sb, "package memlib\n\n")

	generate_mnemonic_enum(&sb, gen)
	generate_mnemonic_strings(&sb, gen)
	strings.write_string(&sb, INVARIANT_CONTENT)
	strings.write_string(&sb, "\n")
	generate_prefix_table(&sb)
	generate_decode_maps(&sb, gen)
	generate_group_tables(&sb, gen)
	generate_fpu_tables(&sb, gen)
	generate_variant_tables(&sb, gen)
	generate_special_tables(&sb, gen)

	ok := os.write_entire_file(output_path, transmute([]u8)strings.to_string(sb))
	if !ok {
		fmt.eprintfln("Error writing output file: %s", output_path)
		os.exit(1)
	}

	fmt.printfln("Generated %s", output_path)
}

generate_mnemonic_enum :: proc(sb: ^strings.Builder, gen: ^Generator) {
	strings.write_string(sb, "Mnemonic :: enum u16 {\n\tINVALID = 0,\n")
	for mnem in gen.mnemonic_list {
		ident := mnemonic_to_ident(mnem)
		fmt.sbprintf(sb, "\t%s,\n", ident)
	}
	strings.write_string(sb, "\t_COUNT,\n}\n\n")
}

generate_mnemonic_strings :: proc(sb: ^strings.Builder, gen: ^Generator) {
	strings.write_string(
		sb,
		"@(rodata)\nmnemonic_strings := #partial [Mnemonic]string{\n\t.INVALID = \"</3\",\n",
	)
	for mnem in gen.mnemonic_list {
		ident := mnemonic_to_ident(mnem)
		lower := strings.to_lower(mnem)
		fmt.sbprintf(sb, "\t.%s = \"%s\",\n", ident, lower)
	}
	strings.write_string(sb, "}\n\n")
}

generate_prefix_table :: proc(sb: ^strings.Builder) {
	strings.write_string(sb, "@(rodata)\n")
	strings.write_string(sb, "prefix_table := [256]u8{\n")

	for i in 0 ..< 256 {
		val: u8 = 0xF0
		switch u8(i) {
		case 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65:
			val = 0x00
		case 0x66:
			val = 0x30
		case 0x67:
			val = 0x00
		case 0xF0:
			val = 0x00
		case 0xF2:
			val = 0x20
		case 0xF3:
			val = 0x10
		}

		if i % 16 == 0 do fmt.sbprintf(sb, "\t")
		fmt.sbprintf(sb, "0x%02X", val)
		if i < 255 do strings.write_string(sb, ", ")
		if i % 16 == 15 do strings.write_string(sb, "\n")
	}

	strings.write_string(sb, "}\n\n")
}

generate_decode_maps :: proc(sb: ^strings.Builder, gen: ^Generator) {
	emit_map :: proc(
		sb: ^strings.Builder,
		name: string,
		map_data: ^[4][256]Flat_Entry,
		gen: ^Generator,
	) {
		fmt.sbprintf(sb, "@(rodata)\n%s := [4][256]Opcode_Full{{\n", name)

		for p in 0 ..< 4 {
			strings.write_string(sb, "\t{\n")

			for o in 0 ..< 256 {
				e := map_data[p][o]
				mnem_str := "INVALID"
				if e.mnemonic != MNEMONIC_INVALID && int(e.mnemonic) <= len(gen.mnemonic_list) {
					mnem_str = mnemonic_to_ident(gen.mnemonic_list[int(e.mnemonic) - 1])
				}

				if o % 4 == 0 do strings.write_string(sb, "\t\t")
				fmt.sbprintf(
					sb,
					"{{0x%02X, .%s, .%s, %d, %d, {{}}}}",
					e.desc,
					mnem_str,
					isa_ext_string(e.isa),
					e.group_id,
					e.secondary_id,
				)
				if o < 255 do strings.write_string(sb, ", ")
				if o % 4 == 3 do strings.write_string(sb, "\n")
			}

			strings.write_string(sb, "\t},\n")
		}

		strings.write_string(sb, "}\n\n")
	}

	emit_map(sb, "decode_map_1", &gen.map_1, gen)
	emit_map(sb, "decode_map_2", &gen.map_2, gen)
	emit_map(sb, "decode_map_38", &gen.map_38, gen)
	emit_map(sb, "decode_map_3A", &gen.map_3A, gen)
}

generate_group_tables :: proc(sb: ^strings.Builder, gen: ^Generator) {
	if len(gen.group_entries) == 0 do return

	for &group, i in gen.group_entries {
		prefix_names := [4]string{"NP", "F3", "F2", "66"}
		table_names := [2]string{"1", "2"}

		if group.has_mod_split {
			fmt.sbprintf(
				sb,
				"@(rodata)\ngroup_%s_%02X_%s_mem := [8]Group_Desc{{\n\t",
				table_names[group.table],
				group.opcode,
				prefix_names[group.prefix],
			)
			for r in 0 ..< 8 {
				e := group.mem[r]
				mnem_str := "INVALID"
				if e.mnemonic != MNEMONIC_INVALID && int(e.mnemonic) <= len(gen.mnemonic_list) {
					mnem_str = mnemonic_to_ident(gen.mnemonic_list[int(e.mnemonic) - 1])
				}
				fmt.sbprintf(
					sb,
					"{{0x%02X, .%s, .%s, %d}}",
					e.desc,
					mnem_str,
					isa_ext_string(e.isa),
					e.variant_id,
				)
				if r < 7 do strings.write_string(sb, ", ")
				if r == 3 do strings.write_string(sb, "\n\t")
			}
			strings.write_string(sb, "\n}\n")

			fmt.sbprintf(
				sb,
				"@(rodata)\ngroup_%s_%02X_%s_reg := [8]Group_Desc{{\n\t",
				table_names[group.table],
				group.opcode,
				prefix_names[group.prefix],
			)
			for r in 0 ..< 8 {
				e := group.reg[r]
				mnem_str := "INVALID"
				if e.mnemonic != MNEMONIC_INVALID && int(e.mnemonic) <= len(gen.mnemonic_list) {
					mnem_str = mnemonic_to_ident(gen.mnemonic_list[int(e.mnemonic) - 1])
				}
				fmt.sbprintf(
					sb,
					"{{0x%02X, .%s, .%s, %d}}",
					e.desc,
					mnem_str,
					isa_ext_string(e.isa),
					e.variant_id,
				)
				if r < 7 do strings.write_string(sb, ", ")
				if r == 3 do strings.write_string(sb, "\n\t")
			}
			strings.write_string(sb, "\n}\n\n")
		} else {
			fmt.sbprintf(
				sb,
				"@(rodata)\ngroup_%s_%02X_%s := [8]Group_Desc{{\n\t",
				table_names[group.table],
				group.opcode,
				prefix_names[group.prefix],
			)
			for r in 0 ..< 8 {
				e := group.mem[r]
				mnem_str := "INVALID"
				if e.mnemonic != MNEMONIC_INVALID && int(e.mnemonic) <= len(gen.mnemonic_list) {
					mnem_str = mnemonic_to_ident(gen.mnemonic_list[int(e.mnemonic) - 1])
				}
				fmt.sbprintf(
					sb,
					"{{0x%02X, .%s, .%s, %d}}",
					e.desc,
					mnem_str,
					isa_ext_string(e.isa),
					e.variant_id,
				)
				if r < 7 do strings.write_string(sb, ", ")
				if r == 3 do strings.write_string(sb, "\n\t")
			}
			strings.write_string(sb, "\n}\n\n")
		}
	}

	strings.write_string(sb, "group_table_mem := [?]^[8]Group_Desc{\n")

	for &group, i in gen.group_entries {
		prefix_names := [4]string{"NP", "F3", "F2", "66"}
		table_names := [2]string{"1", "2"}

		if group.has_mod_split {
			fmt.sbprintf(
				sb,
				"\t&group_%s_%02X_%s_mem,\n",
				table_names[group.table],
				group.opcode,
				prefix_names[group.prefix],
			)
		} else {
			fmt.sbprintf(
				sb,
				"\t&group_%s_%02X_%s,\n",
				table_names[group.table],
				group.opcode,
				prefix_names[group.prefix],
			)
		}
	}
	strings.write_string(sb, "}\n\n")

	strings.write_string(sb, "group_table_reg := [?]^[8]Group_Desc{\n")

	for &group, i in gen.group_entries {
		prefix_names := [4]string{"NP", "F3", "F2", "66"}
		table_names := [2]string{"1", "2"}

		if group.has_mod_split {
			fmt.sbprintf(
				sb,
				"\t&group_%s_%02X_%s_reg,\n",
				table_names[group.table],
				group.opcode,
				prefix_names[group.prefix],
			)
		} else {
			fmt.sbprintf(
				sb,
				"\t&group_%s_%02X_%s,\n",
				table_names[group.table],
				group.opcode,
				prefix_names[group.prefix],
			)
		}
	}
	strings.write_string(sb, "}\n\n")
}

generate_fpu_tables :: proc(sb: ^strings.Builder, gen: ^Generator) {
	fpu_names := [8]string{"D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF"}

	for fpu_idx in 0 ..< 8 {
		has_entries := false
		for sec_idx in 0 ..< 64 {
			if gen.fpu_reg_tables[fpu_idx][sec_idx].mnemonic != MNEMONIC_INVALID {
				has_entries = true
				break
			}
		}

		if !has_entries do continue

		fmt.sbprintf(sb, "@(rodata)\nfpu_%s_reg := [64]Mnemonic{{\n", fpu_names[fpu_idx])

		for sec_idx in 0 ..< 64 {
			if sec_idx % 8 == 0 do strings.write_string(sb, "\t")

			e := gen.fpu_reg_tables[fpu_idx][sec_idx]
			mnem_str := "INVALID"
			if e.mnemonic != MNEMONIC_INVALID && int(e.mnemonic) <= len(gen.mnemonic_list) {
				mnem_str = mnemonic_to_ident(gen.mnemonic_list[int(e.mnemonic) - 1])
			}

			fmt.sbprintf(sb, ".%s", mnem_str)
			if sec_idx < 63 do strings.write_string(sb, ", ")
			if sec_idx % 8 == 7 do strings.write_string(sb, "\n")
		}

		strings.write_string(sb, "}\n\n")
	}

	strings.write_string(sb, "fpu_reg_lookup := [8]^[64]Mnemonic{\n")

	for fpu_idx in 0 ..< 8 {
		has_entries := false
		for sec_idx in 0 ..< 64 {
			if gen.fpu_reg_tables[fpu_idx][sec_idx].mnemonic != MNEMONIC_INVALID {
				has_entries = true
				break
			}
		}

		if has_entries {
			fmt.sbprintf(sb, "\t&fpu_%s_reg,\n", fpu_names[fpu_idx])
		} else {
			strings.write_string(sb, "\tnil,\n")
		}
	}

	strings.write_string(sb, "}\n\n")
}

generate_variant_tables :: proc(sb: ^strings.Builder, gen: ^Generator) {
	if len(gen.variants) == 0 do return

	strings.write_string(sb, "@(rodata)\n")
	strings.write_string(sb, "mnemonic_variant_table := [?]Mnemonic_Variant {\n")

	for v in gen.variants {
		prefix_names := [4]string{"PREFIX_NP", "PREFIX_F3", "PREFIX_F2", "PREFIX_66"}
		handler_names := [?]string {
			"Simple",
			"Opsize_16_32_64",
			"Mode32_64",
			"RexW",
			"Mod_Mem_Reg",
			"Fwait",
		}

		mnem1 := variant_mnemonic_str(v.variants[0], gen)
		mnem2 := variant_mnemonic_str(v.variants[1], gen)
		mnem3 := variant_mnemonic_str(v.variants[2], gen)

		fmt.sbprintf(
			sb,
			"\t{{%d, %s, 0x%02X, .%s, {{.%s, .%s, .%s}}}},\n",
			v.opcode_map,
			prefix_names[v.prefix_state],
			v.opcode,
			handler_names[int(v.handler)],
			mnem1,
			mnem2,
			mnem3,
		)
	}

	strings.write_string(sb, "}\n\n")

	strings.write_string(
		sb,
		"find_mnemonic_variant :: proc \"contextless\" (opcode_map: u8, prefix_state: u8, opcode: u8) -> ^Mnemonic_Variant {\n",
	)
	strings.write_string(sb, "\tfor &entry in mnemonic_variant_table {\n")
	strings.write_string(sb, "\t\tif entry.opcode_map == opcode_map &&\n")
	strings.write_string(sb, "\t\t   entry.prefix_state == prefix_state &&\n")
	strings.write_string(sb, "\t\t   entry.opcode == opcode {\n")
	strings.write_string(sb, "\t\t\treturn &entry\n")
	strings.write_string(sb, "\t\t}\n")
	strings.write_string(sb, "\t}\n")
	strings.write_string(sb, "\treturn nil\n")
	strings.write_string(sb, "}\n\n")

	strings.write_string(sb, "@(rodata)\n")
	strings.write_string(sb, "fpu_fwait_variants := [?][2]Mnemonic {\n")

	fwait_pairs := [][2]string {
		{"FNSAVE", "FSAVE"},
		{"FNSTCW", "FSTCW"},
		{"FNSTENV", "FSTENV"},
		{"FNSTSW", "FSTSW"},
		{"FNCLEX", "FCLEX"},
		{"FNINIT", "FINIT"},
	}

	for pair in fwait_pairs {
		mnem0 := variant_mnemonic_str(pair[0], gen)
		mnem1 := variant_mnemonic_str(pair[1], gen)
		fmt.sbprintf(sb, "\t{{.%s, .%s}},\n", mnem0, mnem1)
	}

	strings.write_string(sb, "}\n\n")
}

variant_mnemonic_str :: proc(mnem: string, gen: ^Generator) -> string {
	if mnem == "" do return "INVALID"
	return mnemonic_to_ident(mnem)
}

generate_special_tables :: proc(sb: ^strings.Builder, gen: ^Generator) {
	strings.write_string(sb, "@(rodata)\n")
	strings.write_string(sb, "modrm_0f01_secondary := [64]Mnemonic {\n")

	secondary_0f01 := [64]string {
		"",
		"VMCALL",
		"VMLAUNCH",
		"VMRESUME",
		"VMXOFF",
		"",
		"",
		"",
		"MONITOR",
		"MWAIT",
		"",
		"",
		"",
		"",
		"",
		"",
		"XGETBV",
		"XSETBV",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		"SWAPGS",
		"RDTSCP",
		"",
		"",
		"",
		"",
		"",
		"",
	}

	for i in 0 ..< 64 {
		if i % 8 == 0 do strings.write_string(sb, "\t")

		mnem := secondary_0f01[i]
		if mnem == "" {
			strings.write_string(sb, ".INVALID")
		} else {
			fmt.sbprintf(sb, ".%s", mnemonic_to_ident(mnem))
		}

		if i < 63 do strings.write_string(sb, ", ")
		if i % 8 == 7 do strings.write_string(sb, "\n")
	}

	strings.write_string(sb, "}\n\n")

	strings.write_string(sb, "@(rodata)\n")
	strings.write_string(sb, "two_byte_overrides := [256]Mnemonic {\n")

	for i in 0 ..< 256 {
		if i % 16 == 0 do strings.write_string(sb, "\t")

		switch i {
		case 0x05:
			strings.write_string(sb, ".SYSCALL")
		case 0x07:
			strings.write_string(sb, ".SYSRET")
		case:
			strings.write_string(sb, ".INVALID")
		}

		if i < 255 do strings.write_string(sb, ", ")
		if i % 16 == 15 do strings.write_string(sb, "\n")
	}

	strings.write_string(sb, "}\n\n")

	strings.write_string(sb, "secondary_tables := [10]^[64]Mnemonic {\n")
	strings.write_string(sb, "\tnil,\n")

	fpu_names := [8]string{"D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF"}
	for fpu_idx in 0 ..< 8 {
		has_entries := false
		for sec_idx in 0 ..< 64 {
			if gen.fpu_reg_tables[fpu_idx][sec_idx].mnemonic != MNEMONIC_INVALID {
				has_entries = true
				break
			}
		}
		if has_entries {
			fmt.sbprintf(sb, "\t&fpu_%s_reg,\n", fpu_names[fpu_idx])
		} else {
			strings.write_string(sb, "\tnil,\n")
		}
	}

	strings.write_string(sb, "\t&modrm_0f01_secondary,\n")
	strings.write_string(sb, "}\n\n")

	if len(gen.group_variants) > 0 {
		strings.write_string(sb, "@(rodata)\n")
		fmt.sbprintf(
			sb,
			"group_variant_table := [%d]Group_Variant {{\n",
			len(gen.group_variants) + 1,
		)
		strings.write_string(sb, "\t{.Simple, {.INVALID, .INVALID}},\n")

		for &v, i in gen.group_variants {
			mnem1 := "INVALID"
			mnem2 := "INVALID"
			if v.variants[0] != "" {
				mnem1 = mnemonic_to_ident(v.variants[0])
			}
			if v.variants[1] != "" {
				mnem2 = mnemonic_to_ident(v.variants[1])
			}
			fmt.sbprintf(
				sb,
				"\t{{.%s, {{.%s, .%s}}}},\n",
				variant_handler_str(v.handler),
				mnem1,
				mnem2,
			)
		}

		strings.write_string(sb, "}\n\n")
	}
}
