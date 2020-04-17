"""
how to compute b**n mod m effectively
the algorithm employs the binary expansion of the exponent n
"""

def modularExp(b, n, m):
	assert(b >= 0 and n >= 0 and m > 0)
	b = b % m
	tmp = b
	result = 1
	while n != 0:
		if n%2 == 1:
			result = (result*tmp)%m
		tmp = (tmp*tmp)%m
		n /= 2
	return result

assert(modularExp(3, 644, 645) == 3**644%645) # 36
assert(modularExp(9999, 9999, 8888) == 9999**9999%8888) # 1111
