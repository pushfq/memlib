#+build !i386
#+build !amd64

package memlib

@(private = "package")
_find_pattern_impl :: proc(pat: ^Pattern, text: []u8) -> int {
	return find_pattern_simple(pat, text)
}
