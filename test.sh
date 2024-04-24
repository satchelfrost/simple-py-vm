assert_test() {
    python3 pyvm.py tests/$1 -l2
    if [ $? -eq 0 ]; then
        echo "[OK] "$1
    else
        echo "[Failed]" $1
    fi
}

echo "Running assertion tests...\n"

assert_test assign.py
assert_test compare.py
assert_test expr.py
assert_test fact.py
assert_test fib.py
assert_test func.py
assert_test if.py
assert_test number.py
assert_test recur.py

echo "\nRunning tests with output..."

python3 pyvm.py tests/while.py -l2
python3 pyvm.py tests/print.py -l2
python3 pyvm.py tests/scope.py -l2
