#+build i386, amd64
package memlib

import "base:intrinsics"
import "core:simd"
import "core:simd/x86"

@(private = "package")
_find_pattern_impl :: proc(pat: ^Pattern, text: []u8) -> int {
	if len(text) >= 64 do return find_pattern_simd(pat, text)
	return find_pattern_simple(pat, text)
}

@(private = "file")
@(enable_target_feature = "sse2")
movemask :: #force_inline proc "contextless" (v: simd.u8x16) -> u64 {
	return u64(x86._mm_movemask_epi8(transmute(x86.__m128i)v))
}

@(private = "file")
@(enable_target_feature = "sse2")
find_pattern_simd :: proc(pat: ^Pattern, text: []u8) -> int #no_bounds_check {
	end := len(text) - pat.size
	text_ptr := raw_data(text)
	num_chunks := pat.padded_size >> 4

	pat_vecs: [CHUNK_COUNT]simd.u8x16 = ---
	req_vecs: [CHUNK_COUNT]simd.u8x16 = ---
	for c in 0 ..< num_chunks {
		pat_vecs[c] = intrinsics.unaligned_load(cast(^simd.u8x16)&pat.data[c << 4])
		req_vecs[c] = pat.required_vecs[c]
	}

	first_byte := pat.data[0]
	last_byte := pat.data[pat.size - 1]
	search_first := simd.u8x16(first_byte)
	search_last := simd.u8x16(last_byte)
	last_off := pat.size - 1

	if num_chunks == 1 {
		return find_pattern_single_chunk(
			text_ptr,
			end,
			last_off,
			search_first,
			search_last,
			first_byte,
			last_byte,
			pat_vecs[0],
			req_vecs[0],
		)
	}

	return find_pattern_multi_chunk(
		text_ptr,
		end,
		last_off,
		num_chunks,
		search_first,
		search_last,
		first_byte,
		last_byte,
		&pat_vecs,
		&req_vecs,
	)
}

@(private = "file")
@(enable_target_feature = "sse2")
find_pattern_single_chunk :: proc "contextless" (
	text_ptr: [^]u8,
	end: int,
	last_off: int,
	search_first: simd.u8x16,
	search_last: simd.u8x16,
	first_byte: u8,
	last_byte: u8,
	pat_vec: simd.u8x16,
	req_vec: simd.u8x16,
) -> int #no_bounds_check {
	BLOCK_SIZE :: 128
	PREFETCH_DIST :: BLOCK_SIZE * 12

	i := 0

	for i <= end - BLOCK_SIZE {
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST], 0)
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST + 64], 0)
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST + 128], 0)
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST + 192], 0)

		v0f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i])
		v0l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + last_off])
		v1f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 16])
		v1l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 16 + last_off])
		v2f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 32])
		v2l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 32 + last_off])
		v3f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 48])
		v3l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 48 + last_off])
		v4f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 64])
		v4l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 64 + last_off])
		v5f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 80])
		v5l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 80 + last_off])
		v6f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 96])
		v6l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 96 + last_off])
		v7f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 112])
		v7l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 112 + last_off])

		m0 := simd.lanes_eq(v0f, search_first) & simd.lanes_eq(v0l, search_last)
		m1 := simd.lanes_eq(v1f, search_first) & simd.lanes_eq(v1l, search_last)
		m2 := simd.lanes_eq(v2f, search_first) & simd.lanes_eq(v2l, search_last)
		m3 := simd.lanes_eq(v3f, search_first) & simd.lanes_eq(v3l, search_last)
		m4 := simd.lanes_eq(v4f, search_first) & simd.lanes_eq(v4l, search_last)
		m5 := simd.lanes_eq(v5f, search_first) & simd.lanes_eq(v5l, search_last)
		m6 := simd.lanes_eq(v6f, search_first) & simd.lanes_eq(v6l, search_last)
		m7 := simd.lanes_eq(v7f, search_first) & simd.lanes_eq(v7l, search_last)

		combined := m0 | m1 | m2 | m3 | m4 | m5 | m6 | m7
		if simd.reduce_or(combined) == 0 {
			i += BLOCK_SIZE
			continue
		}

		bits_lo :=
			movemask(m0) | (movemask(m1) << 16) | (movemask(m2) << 32) | (movemask(m3) << 48)
		bits_hi :=
			movemask(m4) | (movemask(m5) << 16) | (movemask(m6) << 32) | (movemask(m7) << 48)

		for bits_lo != 0 {
			bit := intrinsics.count_trailing_zeros(bits_lo)
			pos := i + int(bit)
			if pos <= end {
				text_vec := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[pos])
				diff := (text_vec ~ pat_vec) & req_vec
				if simd.reduce_or(diff) == 0 do return pos
			}
			bits_lo &= bits_lo - 1
		}
		for bits_hi != 0 {
			bit := intrinsics.count_trailing_zeros(bits_hi)
			pos := i + 64 + int(bit)
			if pos <= end {
				text_vec := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[pos])
				diff := (text_vec ~ pat_vec) & req_vec
				if simd.reduce_or(diff) == 0 do return pos
			}
			bits_hi &= bits_hi - 1
		}

		i += BLOCK_SIZE
	}

	for i <= end - CHUNK_SIZE {
		vf := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i])
		vl := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + last_off])
		m := simd.lanes_eq(vf, search_first) & simd.lanes_eq(vl, search_last)

		bits := u16(movemask(m))
		for bits != 0 {
			bit := intrinsics.count_trailing_zeros(bits)
			pos := i + int(bit)
			if pos <= end {
				text_vec := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[pos])
				diff := (text_vec ~ pat_vec) & req_vec
				if simd.reduce_or(diff) == 0 do return pos
			}
			bits &= bits - 1
		}
		i += CHUNK_SIZE
	}

	for i <= end {
		if text_ptr[i] == first_byte && text_ptr[i + last_off] == last_byte {
			text_vec := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i])
			diff := (text_vec ~ pat_vec) & req_vec
			if simd.reduce_or(diff) == 0 do return i
		}
		i += 1
	}

	return -1
}

@(private = "file")
@(enable_target_feature = "sse2")
find_pattern_multi_chunk :: proc "contextless" (
	text_ptr: [^]u8,
	end: int,
	last_off: int,
	num_chunks: int,
	search_first: simd.u8x16,
	search_last: simd.u8x16,
	first_byte: u8,
	last_byte: u8,
	pat_vecs: ^[CHUNK_COUNT]simd.u8x16,
	req_vecs: ^[CHUNK_COUNT]simd.u8x16,
) -> int #no_bounds_check {
	BLOCK_SIZE :: 128
	PREFETCH_DIST :: BLOCK_SIZE * 12

	i := 0

	for i <= end - BLOCK_SIZE {
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST], 0)
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST + 64], 0)
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST + 128], 0)
		intrinsics.prefetch_read_data(&text_ptr[i + PREFETCH_DIST + 192], 0)

		v0f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i])
		v0l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + last_off])
		v1f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 16])
		v1l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 16 + last_off])
		v2f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 32])
		v2l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 32 + last_off])
		v3f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 48])
		v3l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 48 + last_off])
		v4f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 64])
		v4l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 64 + last_off])
		v5f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 80])
		v5l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 80 + last_off])
		v6f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 96])
		v6l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 96 + last_off])
		v7f := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 112])
		v7l := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + 112 + last_off])

		m0 := simd.lanes_eq(v0f, search_first) & simd.lanes_eq(v0l, search_last)
		m1 := simd.lanes_eq(v1f, search_first) & simd.lanes_eq(v1l, search_last)
		m2 := simd.lanes_eq(v2f, search_first) & simd.lanes_eq(v2l, search_last)
		m3 := simd.lanes_eq(v3f, search_first) & simd.lanes_eq(v3l, search_last)
		m4 := simd.lanes_eq(v4f, search_first) & simd.lanes_eq(v4l, search_last)
		m5 := simd.lanes_eq(v5f, search_first) & simd.lanes_eq(v5l, search_last)
		m6 := simd.lanes_eq(v6f, search_first) & simd.lanes_eq(v6l, search_last)
		m7 := simd.lanes_eq(v7f, search_first) & simd.lanes_eq(v7l, search_last)

		combined := m0 | m1 | m2 | m3 | m4 | m5 | m6 | m7
		if simd.reduce_or(combined) == 0 {
			i += BLOCK_SIZE
			continue
		}

		bits_lo :=
			movemask(m0) | (movemask(m1) << 16) | (movemask(m2) << 32) | (movemask(m3) << 48)
		bits_hi :=
			movemask(m4) | (movemask(m5) << 16) | (movemask(m6) << 32) | (movemask(m7) << 48)

		for bits_lo != 0 {
			bit := intrinsics.count_trailing_zeros(bits_lo)
			pos := i + int(bit)
			if pos <= end && verify_match(text_ptr, pos, pat_vecs, req_vecs, num_chunks) {
				return pos
			}
			bits_lo &= bits_lo - 1
		}
		for bits_hi != 0 {
			bit := intrinsics.count_trailing_zeros(bits_hi)
			pos := i + 64 + int(bit)
			if pos <= end && verify_match(text_ptr, pos, pat_vecs, req_vecs, num_chunks) {
				return pos
			}
			bits_hi &= bits_hi - 1
		}

		i += BLOCK_SIZE
	}

	for i <= end - CHUNK_SIZE {
		vf := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i])
		vl := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[i + last_off])
		m := simd.lanes_eq(vf, search_first) & simd.lanes_eq(vl, search_last)

		bits := u16(movemask(m))
		for bits != 0 {
			bit := intrinsics.count_trailing_zeros(bits)
			pos := i + int(bit)
			if pos <= end && verify_match(text_ptr, pos, pat_vecs, req_vecs, num_chunks) {
				return pos
			}
			bits &= bits - 1
		}
		i += CHUNK_SIZE
	}

	for i <= end {
		if text_ptr[i] == first_byte && text_ptr[i + last_off] == last_byte {
			if verify_match(text_ptr, i, pat_vecs, req_vecs, num_chunks) {
				return i
			}
		}
		i += 1
	}

	return -1
}

@(private = "file")
verify_match :: #force_inline proc "contextless" (
	text_ptr: [^]u8,
	pos: int,
	pat_vecs: ^[CHUNK_COUNT]simd.u8x16,
	req_vecs: ^[CHUNK_COUNT]simd.u8x16,
	num_chunks: int,
) -> bool #no_bounds_check {
	for c in 0 ..< num_chunks {
		text_vec := intrinsics.unaligned_load(cast(^simd.u8x16)&text_ptr[pos + (c << 4)])
		diff := (text_vec ~ pat_vecs[c]) & req_vecs[c]
		if simd.reduce_or(diff) != 0 {
			return false
		}
	}
	return true
}
