package utils

func GCD(i, b int) int {
	if b == 0 {
		return i;
	}
	return GCD(b,i%b);
}
