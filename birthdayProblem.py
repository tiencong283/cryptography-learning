from __future__ import print_function

"""
find probability that in a group of n people at least two have the same birthday
it's assumed that a year has 365 possible days and they are equally likely

some observations:
for n > 23: p > 50%
for n = 70: p ~ 99.9%
for n > 365: p = 1
"""

def p(n):
	if n > 365:
		return 100
	ret = 1
	for i in range(n):
		ret *= (1 - i/365.0)
	return 100*(1-ret)

print("p(23) = {}".format(p(23)))
print("p(70) = {}".format(p(70)))
