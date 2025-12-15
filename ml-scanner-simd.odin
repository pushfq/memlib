package memlib

import "base:intrinsics"
import "core:simd"

SIMD_256 :: #config(SIMD_256, false)

@(private = "package")
find_pattern_simd :: proc(pat: ^Pattern, text: []u8) -> int {
	when SIMD_256 {
		return find_pattern_impl(#simd[32]u8, u32, pat, text)
	} else {
		return find_pattern_impl(#simd[16]u8, u16, pat, text)
	}
}

@(private = "file")
find_pattern_impl :: proc(
	$Vec: typeid,
	$Mask: typeid,
	pat: ^Pattern,
	text: []u8,
) -> int #no_bounds_check {
	WIDTH :: size_of(Vec)
	UNROLL :: 8 when WIDTH == 16 else 4
	BLOCK :: WIDTH * UNROLL
	PREFETCH_DIST :: 4096

	if len(text) < pat.size do return -1

	data := raw_data(text)
	num_vecs := (pat.padded_size + WIDTH - 1) / WIDTH

	ctx := Scan_Context(Vec) {
		data     = data,
		end      = len(text) - pat.size,
		pat_v0   = load_vec(Vec, raw_data(pat.data[:]), 0),
		req_v0   = load_vec(Vec, raw_data(pat.required[:]), 0),
		num_vecs = num_vecs,
	}
	if num_vecs >= 2 {
		ctx.pat_v1 = load_vec(Vec, raw_data(pat.data[:]), WIDTH)
		ctx.req_v1 = load_vec(Vec, raw_data(pat.required[:]), WIDTH)
	}

	first := pat.data[0]
	last := pat.data[pat.size - 1]
	last_off := pat.size - 1
	search_f := Vec(first)
	search_l := Vec(last)

	i := 0

	for i <= ctx.end - BLOCK {
		intrinsics.prefetch_read_data(&data[i + PREFETCH_DIST], 1)

		m0 := match_anchors(Vec, data, i, last_off, search_f, search_l)
		m1 := match_anchors(Vec, data, i + WIDTH, last_off, search_f, search_l)
		m2 := match_anchors(Vec, data, i + WIDTH * 2, last_off, search_f, search_l)
		m3 := match_anchors(Vec, data, i + WIDTH * 3, last_off, search_f, search_l)

		combined := m0 | m1 | m2 | m3

		when UNROLL == 8 {
			m4 := match_anchors(Vec, data, i + WIDTH * 4, last_off, search_f, search_l)
			m5 := match_anchors(Vec, data, i + WIDTH * 5, last_off, search_f, search_l)
			m6 := match_anchors(Vec, data, i + WIDTH * 6, last_off, search_f, search_l)
			m7 := match_anchors(Vec, data, i + WIDTH * 7, last_off, search_f, search_l)
			combined = combined | m4 | m5 | m6 | m7
		}

		if extract_mask(Mask, combined) == 0 {
			i += BLOCK
			continue
		}

		if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m0), i); found do return pos
		if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m1), i + WIDTH); found do return pos
		if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m2), i + WIDTH * 2); found do return pos
		if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m3), i + WIDTH * 3); found do return pos

		when UNROLL == 8 {
			if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m4), i + WIDTH * 4); found do return pos
			if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m5), i + WIDTH * 5); found do return pos
			if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m6), i + WIDTH * 6); found do return pos
			if pos, found := scan_bits(Vec, Mask, &ctx, extract_mask(Mask, m7), i + WIDTH * 7); found do return pos
		}

		i += BLOCK
	}

	for i <= ctx.end - WIDTH {
		bits := extract_mask(Mask, match_anchors(Vec, data, i, last_off, search_f, search_l))
		if pos, found := scan_bits(Vec, Mask, &ctx, bits, i); found do return pos
		i += WIDTH
	}

	for i <= ctx.end {
		if data[i] == first && data[i + last_off] == last {
			if verify(Vec, Mask, &ctx, i) do return i
		}
		i += 1
	}

	return -1
}

@(private = "file")
Scan_Context :: struct($Vec: typeid) {
	data:     [^]u8,
	end:      int,
	pat_v0:   Vec,
	req_v0:   Vec,
	pat_v1:   Vec,
	req_v1:   Vec,
	num_vecs: int,
}

@(private = "file")
extract_mask :: #force_inline proc "contextless" ($Mask: typeid, v: $Vec) -> Mask {
	return transmute(Mask)simd.extract_msbs(v)
}

@(private = "file")
load_vec :: #force_inline proc "contextless" ($Vec: typeid, ptr: [^]u8, #any_int off: int) -> Vec {
	return intrinsics.unaligned_load(cast(^Vec)&ptr[off])
}

@(private = "file")
match_anchors :: #force_inline proc "contextless" (
	$Vec: typeid,
	data: [^]u8,
	#any_int off: int,
	last_off: int,
	search_f, search_l: Vec,
) -> Vec {
	f := load_vec(Vec, data, off)
	l := load_vec(Vec, data, off + last_off)
	return simd.lanes_eq(f, search_f) & simd.lanes_eq(l, search_l)
}

@(private = "file")
scan_bits :: #force_inline proc "contextless" (
	$Vec: typeid,
	$Mask: typeid,
	ctx: ^Scan_Context(Vec),
	bits: Mask,
	base: int,
) -> (
	pos: int,
	found: bool,
) #no_bounds_check {
	for b := bits; b != 0; b &= b - 1 {
		pos = base + int(intrinsics.count_trailing_zeros(b))
		if pos <= ctx.end && verify(Vec, Mask, ctx, pos) {
			return pos, true
		}
	}
	return -1, false
}

@(private = "file")
verify :: #force_inline proc "contextless" (
	$Vec: typeid,
	$Mask: typeid,
	ctx: ^Scan_Context(Vec),
	pos: int,
) -> bool #no_bounds_check {
	WIDTH :: size_of(Vec)

	text0 := load_vec(Vec, ctx.data, pos)
	diff0 := (text0 ~ ctx.pat_v0) & ctx.req_v0
	if extract_mask(Mask, diff0) != 0 do return false
	if ctx.num_vecs == 1 do return true

	text1 := load_vec(Vec, ctx.data, pos + WIDTH)
	diff1 := (text1 ~ ctx.pat_v1) & ctx.req_v1
	return extract_mask(Mask, diff1) == 0
}

@(private = "package")
find_pattern_simple :: proc(pat: ^Pattern, text: []u8) -> int #no_bounds_check {
	end := len(text) - pat.size
	outer: for i in 0 ..= end {
		for j in 0 ..< pat.size {
			if pat.required[j] != 0 && text[i + j] != pat.data[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
