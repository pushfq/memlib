package memlib

import "core:simd"

CHUNK_SIZE :: 16
MAX_PATTERN_SIZE :: 128
CHUNK_COUNT :: MAX_PATTERN_SIZE / CHUNK_SIZE

Pattern :: struct #align (64) {
	data:          [MAX_PATTERN_SIZE]u8,
	mask:          [CHUNK_COUNT]u16,
	required_vecs: [CHUNK_COUNT]simd.u8x16,
	size:          int,
	padded_size:   int,
}

@(private = "file")
HEX_LO :: u64(0x03FF_0000_0000_0000)
@(private = "file")
HEX_HI :: u64(0x0000_007E_0000_007E)

@(private = "file")
is_hex :: #force_inline proc "contextless" (c: u8) -> bool {
	if c >= 128 {
		return false
	}
	m := c < 64 ? HEX_LO : HEX_HI
	return (m >> (c & 63)) & 1 != 0
}

@(private = "file")
to_hex :: #force_inline proc "contextless" (c: u8) -> u8 {
	return (c & 0xF) + (c >> 6) * 9
}

compile_pattern :: proc(ptext: string) -> (pat: Pattern, ok: bool) {
	n := len(ptext)
	i := 0
	out_idx := 0
	wild_bits: u128 = 0

	for i < n {
		if out_idx >= MAX_PATTERN_SIZE {
			return {}, false
		}

		c := ptext[i]

		switch {
		case is_hex(c):
			if i + 1 >= n {
				return {}, false
			}

			c2 := ptext[i + 1]
			if !is_hex(c2) {
				return {}, false
			}

			pat.data[out_idx] = to_hex(c) << 4 | to_hex(c2)
			out_idx += 1
			i += 2

		case c == ' ' || c == '\t':
			i += 1

		case c == '?':
			wild_bits |= 1 << uint(out_idx)
			out_idx += 1
			i += 1

		case c == '{':
			out_idx, i, wild_bits = parse_brace_repeat(
				ptext,
				i,
				out_idx,
				wild_bits,
				&pat,
			) or_return

		case:
			return {}, false
		}
	}

	if out_idx == 0 {
		return {}, true
	}

	raw_size := out_idx
	padded_size := (raw_size + CHUNK_SIZE - 1) & ~int(CHUNK_SIZE - 1)

	for k in raw_size ..< padded_size {
		wild_bits |= 1 << uint(k)
	}

	for chunk in 0 ..< CHUNK_COUNT {
		pat.mask[chunk] = u16(wild_bits >> uint(chunk * CHUNK_SIZE))
		m := pat.mask[chunk]
		req_bytes: [CHUNK_SIZE]u8
		for lane in 0 ..< CHUNK_SIZE {
			req_bytes[lane] = ((m >> uint(lane)) & 1) == 1 ? 0x00 : 0xFF
		}
		pat.required_vecs[chunk] = simd.from_array(req_bytes)
	}

	pat.size = raw_size
	pat.padded_size = padded_size

	return pat, true
}

@(private = "file")
parse_brace_repeat :: proc(
	src: string,
	start: int,
	out_idx: int,
	wild_bits: u128,
	pat: ^Pattern,
) -> (
	new_out_idx: int,
	new_i: int,
	new_wild_bits: u128,
	ok: bool,
) {
	i := start + 1
	n := len(src)

	colon_pos := -1
	end_pos := -1

	for j := i; j < n; j += 1 {
		c := src[j]
		if c == ':' && colon_pos < 0 {
			colon_pos = j
		} else if c == '}' {
			end_pos = j
			break
		}
	}

	if end_pos < 0 || colon_pos < 0 {
		return 0, 0, 0, false
	}

	value_len := colon_pos - i
	is_wildcard := value_len == 1 && src[i] == '?'
	byte_val: u8 = 0

	if !is_wildcard {
		if value_len != 2 {
			return 0, 0, 0, false
		}
		c1, c2 := src[i], src[i + 1]
		if !is_hex(c1) || !is_hex(c2) {
			return 0, 0, 0, false
		}
		byte_val = to_hex(c1) << 4 | to_hex(c2)
	}

	if colon_pos + 1 >= end_pos {
		return 0, 0, 0, false
	}

	count := 0
	for j := colon_pos + 1; j < end_pos; j += 1 {
		d := src[j]
		if d < '0' || d > '9' {
			return 0, 0, 0, false
		}
		count = count * 10 + int(d - '0')
		if count > MAX_PATTERN_SIZE {
			return 0, 0, 0, false
		}
	}

	if count == 0 || out_idx + count > MAX_PATTERN_SIZE {
		return 0, 0, 0, false
	}

	new_wild_bits = wild_bits

	if is_wildcard {
		for j in 0 ..< count {
			new_wild_bits |= 1 << uint(out_idx + j)
		}
	}

	for j in 0 ..< count {
		pat.data[out_idx + j] = byte_val
	}

	return out_idx + count, end_pos + 1, new_wild_bits, true
}

@(require_results)
find_pattern :: proc(pat: ^Pattern, text: []u8) -> int {
	if pat.size == 0 || pat.size > len(text) do return -1
	return _find_pattern_impl(pat, text)
}

@(private = "package")
find_pattern_simple :: proc(pat: ^Pattern, text: []u8) -> int #no_bounds_check {
	end := len(text) - pat.size
	outer: for i in 0 ..= end {
		for j in 0 ..< pat.size {
			chunk := j >> 4
			bit := u16(1) << uint(j & (CHUNK_SIZE - 1))
			if (pat.mask[chunk] & bit) == 0 && text[i + j] != pat.data[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
