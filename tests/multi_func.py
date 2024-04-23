a = 2
b = 3
def my_func(a):
    b = 5
    print(a) # 4
    print(b) # 5
    def other_func(c):
        d = 7
        print(c) # 6
        print(d) # 7
    other_func(6)

print(a) # 2
print(b) # 3
my_func(a + b - 1)
