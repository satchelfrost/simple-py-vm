def fact(n):
    a = 42
    if n == 0:
        return 1
    return n * fact(n - 1)

a = fact(5)
assert a == 120
