i     = 10 
fib1  = 0
fib2  = 1
count = 2
while count < i:
    print(fib1)
    tmp   = fib1 + fib2
    fib1  = fib2
    fib2  = tmp
    count = count + 1
