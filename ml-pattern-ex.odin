package memlib

import "core:mem"

Op :: enum u8 {
	End,
	Byte,
	Skip,
	Many,
	Save,
	Rel8,
	Rel32,
	Read_U8,
	Read_I8,
	Read_U16,
	Read_I16,
	Read_U32,
	Read_I32,
	Read_U64,
	Read_I64,
	Push,
	Pop,
}

MAX_OPS :: 256
MAX_SAVES :: 16
MAX_STACK :: 4

Pattern_Ex :: struct {
	anchor:     Pattern,
	anchor_off: int,
	ops:        [MAX_OPS]u8,
	op_count:   int,
	save_count: int,
}

Match_Result :: struct {
	pos:   int,
	saves: [MAX_SAVES]int,
	ok:    bool,
}

@(private = "file")
Compiler :: struct {
	ops:             ^[MAX_OPS]u8,
	op_idx:          int,
	anchor_start:    int,
	anchor_end:      int,
	anchor_byte_pos: int,
	in_anchor:       bool,
	save_idx:        u8,
	byte_pos:        int,
}

@(private = "file")
emit :: proc(c: ^Compiler, op: Op, arg: u8 = 0) -> bool {
	if c.op_idx + 1 >= MAX_OPS do return false
	c.ops[c.op_idx] = u8(op)
	c.ops[c.op_idx + 1] = arg
	c.op_idx += 2
	return true
}

@(private = "file")
end_anchor :: proc(c: ^Compiler) {
	c.in_anchor = false
}

@(private = "file")
extend_anchor :: proc(c: ^Compiler) {
	if c.in_anchor {
		c.anchor_end = c.op_idx + 2
	}
}

@(private = "file")
start_anchor :: proc(c: ^Compiler) {
	if c.anchor_start < 0 {
		c.anchor_start = c.op_idx
		c.anchor_byte_pos = c.byte_pos
		c.in_anchor = true
	}
}

@(private = "file")
parse_number :: proc(src: string, i: ^int) -> int {
	n := len(src)
	result := 0
	for i^ < n && src[i^] >= '0' && src[i^] <= '9' {
		result = result * 10 + int(src[i^] - '0')
		i^ += 1
	}
	return result
}

compile_pattern_ex :: proc(src: string) -> (pat: Pattern_Ex, ok: bool) {
	c := Compiler {
		ops          = &pat.ops,
		anchor_start = -1,
	}

	n := len(src)
	i := 0

	for i < n {
		ch := src[i]

		switch {
		case is_hex(ch):
			if i + 1 >= n do return
			ch2 := src[i + 1]
			if !is_hex(ch2) do return

			start_anchor(&c)
			extend_anchor(&c)
			emit(&c, .Byte, to_hex(ch) << 4 | to_hex(ch2)) or_return
			c.byte_pos += 1
			i += 2

		case ch == ' ' || ch == '\t' || ch == '\n':
			i += 1

		case ch == '?':
			i += 1
			if i < n && src[i] == '?' do i += 1
			extend_anchor(&c)
			emit(&c, .Skip, 1) or_return
			c.byte_pos += 1

		case ch == '[':
			i += 1
			lo := parse_number(src, &i)
			hi := lo

			if i < n && src[i] == '-' {
				i += 1
				hi = parse_number(src, &i)
			}

			if i >= n || src[i] != ']' do return
			i += 1

			if lo == hi {
				if c.in_anchor do c.anchor_end = c.op_idx
				emit(&c, .Skip, u8(min(lo, 255))) or_return
				c.byte_pos += lo
			} else {
				if lo > 0 {
					emit(&c, .Skip, u8(min(lo, 255))) or_return
					c.byte_pos += lo
				}
				end_anchor(&c)
				emit(&c, .Many, u8(min(hi - lo, 255))) or_return
			}

		case ch == '\'':
			end_anchor(&c)
			emit(&c, .Save, c.save_idx) or_return
			c.save_idx += 1
			i += 1

		case ch == '$':
			end_anchor(&c)
			emit(&c, .Rel32, 0) or_return
			i += 1

		case ch == '%':
			end_anchor(&c)
			emit(&c, .Rel8, 0) or_return
			i += 1

		case ch == '{':
			end_anchor(&c)
			if c.op_idx < 2 do return
			prev_op := Op(c.ops[c.op_idx - 2])
			skip: u8
			#partial switch prev_op {
			case .Rel8:
				skip = 1
			case .Rel32:
				skip = 4
			case:
				return
			}
			c.ops[c.op_idx - 2] = u8(Op.Push)
			c.ops[c.op_idx - 1] = skip
			emit(&c, prev_op, 0) or_return
			i += 1

		case ch == '}':
			end_anchor(&c)
			emit(&c, .Pop, 0) or_return
			i += 1

		case ch == 'u' || ch == 'i':
			if i + 1 >= n do return
			signed := ch == 'i'
			size := src[i + 1]
			i += 2

			op: Op
			switch size {
			case '1':
				op = .Read_I8 if signed else .Read_U8
			case '2':
				op = .Read_I16 if signed else .Read_U16
			case '4':
				op = .Read_I32 if signed else .Read_U32
			case '8':
				op = .Read_I64 if signed else .Read_U64
			case:
				return
			}
			emit(&c, op, c.save_idx) or_return
			c.save_idx += 1

		case:
			return
		}
	}

	emit(&c, .End, 0)
	pat.op_count = c.op_idx
	pat.save_count = int(c.save_idx)

	if c.anchor_start >= 0 && c.anchor_end > c.anchor_start {
		pat.anchor_off = c.anchor_byte_pos
		build_anchor(&pat, c.anchor_start, c.anchor_end)
	}

	return pat, true
}

@(private = "file")
build_anchor :: proc(pat: ^Pattern_Ex, start, end: int) {
	out_idx := 0
	wild_bits: u128 = 0

	loop: for i := start; i < end && out_idx < MAX_PATTERN_SIZE; i += 2 {
		op := Op(pat.ops[i])
		arg := pat.ops[i + 1]

		#partial switch op {
		case .Byte:
			pat.anchor.data[out_idx] = arg
			out_idx += 1
		case .Skip:
			for _ in 0 ..< int(arg) {
				if out_idx >= MAX_PATTERN_SIZE do break loop
				wild_bits |= 1 << uint(out_idx)
				out_idx += 1
			}
		case:
			break loop
		}
	}

	if out_idx == 0 do return

	raw_size := out_idx
	padded_size := (raw_size + CHUNK_SIZE - 1) & ~int(CHUNK_SIZE - 1)

	for k in raw_size ..< padded_size {
		wild_bits |= 1 << uint(k)
	}

	num_chunks := padded_size / CHUNK_SIZE
	for chunk in 0 ..< num_chunks {
		pat.anchor.mask[chunk] = u16(wild_bits >> uint(chunk * CHUNK_SIZE))
		m := pat.anchor.mask[chunk]
		base := chunk * CHUNK_SIZE
		for lane in 0 ..< CHUNK_SIZE {
			pat.anchor.required[base + lane] = 0x00 if ((m >> uint(lane)) & 1) == 1 else 0xFF
		}
	}

	pat.anchor.size = raw_size
	pat.anchor.padded_size = padded_size
}

@(private = "file")
read_le :: proc "contextless" (
	$T: typeid,
	data: []u8,
	cursor: int,
) -> (
	val: T,
	ok: bool,
) #no_bounds_check {
	if cursor + size_of(T) > len(data) do return
	mem.copy(&val, &data[cursor], size_of(T))
	return val, true
}

@(private = "file")
execute_ops :: proc(
	pat: ^Pattern_Ex,
	data: []u8,
	start: int,
) -> (
	result: Match_Result,
	ok: bool,
) #no_bounds_check {
	result.pos = start
	cursor := start
	stack: [MAX_STACK]int
	sp := 0
	ip := 0

	for {
		op := Op(pat.ops[ip])
		arg := pat.ops[ip + 1]
		ip += 2

		switch op {
		case .End:
			result.ok = true
			ok = true
			return

		case .Byte:
			if cursor >= len(data) || data[cursor] != arg do return
			cursor += 1

		case .Skip:
			cursor += int(arg)

		case .Many:
			peek_ip := ip
			for peek_ip < pat.op_count && Op(pat.ops[peek_ip]) == .Save {
				peek_ip += 2
			}
			if peek_ip >= pat.op_count do return

			next_op := Op(pat.ops[peek_ip])
			if next_op != .Byte do return

			target := pat.ops[peek_ip + 1]
			limit := min(cursor + int(arg), len(data))

			found := false
			for cursor <= limit {
				if data[cursor] == target {
					found = true
					break
				}
				cursor += 1
			}
			if !found do return

		case .Save:
			result.saves[arg] = cursor

		case .Rel8:
			if cursor >= len(data) do return
			cursor += 1 + int(i8(data[cursor]))

		case .Rel32:
			offset := read_le(i32le, data, cursor) or_return
			cursor += 4 + int(offset)

		case .Read_U8:
			if cursor >= len(data) do return
			result.saves[arg] = int(data[cursor])
			cursor += 1

		case .Read_I8:
			if cursor >= len(data) do return
			result.saves[arg] = int(i8(data[cursor]))
			cursor += 1

		case .Read_U16:
			val := read_le(u16le, data, cursor) or_return
			result.saves[arg] = int(val)
			cursor += 2

		case .Read_I16:
			val := read_le(i16le, data, cursor) or_return
			result.saves[arg] = int(val)
			cursor += 2

		case .Read_U32:
			val := read_le(u32le, data, cursor) or_return
			result.saves[arg] = int(val)
			cursor += 4

		case .Read_I32:
			val := read_le(i32le, data, cursor) or_return
			result.saves[arg] = int(val)
			cursor += 4

		case .Read_U64:
			val := read_le(u64le, data, cursor) or_return
			result.saves[arg] = int(val)
			cursor += 8

		case .Read_I64:
			val := read_le(i64le, data, cursor) or_return
			result.saves[arg] = int(val)
			cursor += 8

		case .Push:
			if sp >= MAX_STACK do return
			stack[sp] = cursor + int(arg)
			sp += 1

		case .Pop:
			if sp <= 0 do return
			sp -= 1
			cursor = stack[sp]
		}

		if cursor < 0 || cursor > len(data) do return
	}
}

@(require_results)
find_pattern_ex :: proc(pat: ^Pattern_Ex, data: []u8) -> Match_Result {
	if pat.anchor.size == 0 {
		result, _ := execute_ops(pat, data, 0)
		return result
	}

	for pos := 0; pos < len(data); {
		candidate := find_pattern(&pat.anchor, data[pos:])
		if candidate < 0 do break

		actual_start := pos + candidate - pat.anchor_off
		if actual_start >= 0 {
			if result, matched := execute_ops(pat, data, actual_start); matched {
				return result
			}
		}

		pos += candidate + 1
	}

	return {}
}

find_all_pattern_ex :: proc(pat: ^Pattern_Ex, data: []u8, results: []Match_Result) -> int {
	count := 0

	for pos := 0; pos < len(data) && count < len(results); {
		candidate := find_pattern(&pat.anchor, data[pos:])
		if candidate < 0 do break

		actual_start := pos + candidate - pat.anchor_off
		if actual_start >= 0 {
			if result, matched := execute_ops(pat, data, actual_start); matched {
				results[count] = result
				count += 1
			}
		}

		pos += candidate + 1
	}

	return count
}
