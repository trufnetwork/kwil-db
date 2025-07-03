package main

func main() {
	recur(100000000)
}

func recur(i int) {
	if i == 0 {
		return
	}

	m[i] = struct{}{}
	recur(i - 1)
}

var m = map[int]struct{}{}
