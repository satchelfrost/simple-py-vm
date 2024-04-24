# Simple Python Virutal Machine
The intent of this project is to learn about virtual machines (VM) by parsing Python source code and generating bytecode for a VM. The VM and bytecode are based directly off of [Section III](https://craftinginterpreters.com/a-bytecode-virtual-machine.html) from the book Crafting Interpreters.

>**__Note__**: It's worth mentioning that Python does have its own bytecode, however since the goal of this project is to learn about VMs and their design, we will ignore that and instead utilize the design from Crafting Interpreters.

## How it works
 The program `pyvm.py` works in two stages:

* Builds an abstract syntax tree ([AST](https://en.wikipedia.org/wiki/Abstract_syntax_tree)), and traverses it to generate bytecode
* Interprets the bytecode with a VM ([process virtual machine](https://en.wikipedia.org/wiki/Virtual_machine) or [stack machine](https://en.wikipedia.org/wiki/Stack_machine))

 Python already has a built-in module `ast`, which can generate an AST. This takes care of all the lexing and parsing in a single line of code:

```python
node = ast.parse(src, filename=args.file)
```

The variable `node` (the root of the tree) can then be traversed using the visitor pattern. As each node in the AST is visited, the compiler uses the information from each node to generate bytecode. This is different from merely visiting the AST nodes and evaulating/executing them as they are encountered (a.k.a a tree-walk interpreter). Instead we compile the bytecode instructions first, and then have the VM execute them afterwards.

The advantages of a stack machine over a tree-walk interpreter are performance, and the ability to have a 'compiled' version of the code that we can execute at any time. In theory, the bytecode is agnostic to any platform, as long as you have a working VM on that platform ([not an original idea](https://en.wikipedia.org/wiki/Java_virtual_machine)).

>**__Note__**: In case it wasn't clear, `pyvm.py` contains both the compiler plus the VM for simplicity.

## Usage
>**__Note__**: The version of python used is 3.10.12, but it will likely work with older versions.

For a list of command line options run:

```bash
python3 pyvm.py -h
```

To run a simple example try the following:

```bash
python3 pyvm.py tests/print.py
```

Which should output

```bash
expect 23
23
```

The default log level is ERROR(2), meaning only errors and progams utilizing `print()` will log anything to the console. Since this is not always useful for debugging, there are two more log levels INFO(1) and DEBUG(0).

For example,

```bash
python3 pyvm.py tests/expr.py
```

or

```bash
python3 pyvm.py tests/expr.py -l2
```

Will not output anything since only an expression is being evalulated. However,

```bash
python3 pyvm.py tests/expr.py -l1
```

will output the following:

```bash
-----------------
| LogLevel.INFO |
-----------------
-----------------
| Nodes visited |
-----------------
Module
Expr
BinOp
BinOp
Constant
Constant
Add
BinOp
Constant
UnaryOp
Constant
Mult
Sub
----------------
| Input Progam |
----------------
3 + 4 - 2 * (-8)
---------------
| Disassembly |
---------------
main:
0000 Opcode.CONST 0 '3'
0002 Opcode.CONST 1 '4'
0004 Opcode.ADD
0005 Opcode.CONST 2 '2'
0007 Opcode.CONST 3 '8'
0009 Opcode.NEG
0010 Opcode.MULT
0011 Opcode.SUB
0012 Opcode.POP
------
| VM |
------
```

The sections should be self-explanatory, however it should be noted that everything before the VM section is the compilation step, and everything after is runtime. In this case, nothing is printed after the VM section since we never called `print()` in `expr.py`. However, we can change this by adjusting the log level again.

```bash
python3 pyvm.py tests/expr.py -l0
```

The same information is printed as before, but now we have more debug information.


```bash
---------------------------------
| Nodes visited (With AST Info) |
---------------------------------
Module(body=[Expr(value=BinOp(left=BinOp(left=Constant(value=3), op=Add(), right=Constant(value=4)), op=Sub(), right=BinOp(left=Constant(value=2), op=Mult(), right=UnaryOp(op=USub(), operand=Constant(value=8)))))], type_ignores=[])
Expr(value=BinOp(left=BinOp(left=Constant(value=3), op=Add(), right=Constant(value=4)), op=Sub(), right=BinOp(left=Constant(value=2), op=Mult(), right=UnaryOp(op=USub(), operand=Constant(value=8)))))
BinOp(left=BinOp(left=Constant(value=3), op=Add(), right=Constant(value=4)), op=Sub(), right=BinOp(left=Constant(value=2), op=Mult(), right=UnaryOp(op=USub(), operand=Constant(value=8))))
BinOp(left=Constant(value=3), op=Add(), right=Constant(value=4))
Constant(value=3)
Constant(value=4)
Add()
BinOp(left=Constant(value=2), op=Mult(), right=UnaryOp(op=USub(), operand=Constant(value=8)))
Constant(value=2)
UnaryOp(op=USub(), operand=Constant(value=8))
Constant(value=8)
Mult()
Sub()
----------------------------
| VM (Stack Trace Enabled) |
----------------------------
0000 Opcode.CONST 3
[3]
0002 Opcode.CONST 4
[3][4]
0004 Opcode.ADD
[7]
0005 Opcode.CONST 2
[7][2]
0007 Opcode.CONST 8
[7][2][8]
0009 Opcode.NEG
[7][2][-8]
0010 Opcode.MULT
[7][-16]
0011 Opcode.SUB
[23]
0012 Opcode.POP
---------
| Stack |
---------
[]
```

Now we can see the VM was actually doing work even though nothing was printed.

## Testing

To run the tests execute the `test.sh` script

```bash
sh test.sh
```

## Slides

Link to [slide deck](https://docs.google.com/presentation/d/1soBNmPVKalS6c8L-6RQac1fnk89sOxcS40-WA8vukx4/edit?usp=sharing)
