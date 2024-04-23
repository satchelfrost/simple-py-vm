import ast
from enum import Enum
import argparse

class LogLevel(Enum):
    DEBUG = 0
    INFO  = 1
    ERROR = 2

class Opcode(Enum):
    ADD          = 0
    SUB          = 1
    MULT         = 2
    DIV          = 3
    AND          = 4
    BIT_AND      = 5
    OR           = 6
    BIT_OR       = 7
    BIT_XOR      = 8
    LT           = 9
    LTE          = 10
    GT           = 11
    GTE          = 12
    EQ           = 13
    NOT_EQ       = 14
    INVERT       = 15
    NOT          = 16
    UADD         = 17
    NEG          = 18
    RET          = 19
    CONST        = 20
    PRINT        = 21
    NIL          = 22
    GET_VAR      = 23
    SET_VAR      = 24
    POP          = 25
    TRUE         = 26
    FALSE        = 27
    ASSERT       = 28
    JMP          = 29
    JMP_IF_FALSE = 30
    LOOP         = 31
    CALL         = 32

binops = {
    Opcode.ADD     : lambda a, b: a +   b,
    Opcode.SUB     : lambda a, b: a -   b,
    Opcode.MULT    : lambda a, b: a *   b,
    Opcode.DIV     : lambda a, b: a /   b,
    Opcode.AND     : lambda a, b: a and b,
    Opcode.BIT_AND : lambda a, b: a &   b,
    Opcode.OR      : lambda a, b: a or  b,
    Opcode.BIT_OR  : lambda a, b: a |   b,
    Opcode.BIT_XOR : lambda a, b: a ^   b,
    Opcode.LT      : lambda a, b: a <   b,
    Opcode.LTE     : lambda a, b: a <=  b,
    Opcode.GT      : lambda a, b: a >   b,
    Opcode.GTE     : lambda a, b: a >=  b,
    Opcode.EQ      : lambda a, b: a ==  b,
    Opcode.NOT_EQ  : lambda a, b: a !=  b,
}

class Function:
    def __init__(self, arity=0):
        self.code      = bytearray()
        self.constants = []
        self.locals    = []
        self.arity     = arity

    def emit_byte(self, byte):
        self.code.append(byte)

    def disass(self):
        offset = 0
        while offset < len(self.code):
            offset = self.disass_instr(offset)

    def disass_instr(self, offset):
        opcode = Opcode(self.code[offset])
        match opcode:
            case Opcode.CONST:
                return self.const_instr(opcode, offset)
            case Opcode.SET_VAR:
                return self.byte_instr(opcode, offset)
            case Opcode.GET_VAR:
                return self.byte_instr(opcode, offset)
            case Opcode.CALL:
                return self.byte_instr(opcode, offset)
            case Opcode.JMP:
                return self.jmp_instr(opcode, 1, offset)
            case Opcode.JMP_IF_FALSE:
                return self.jmp_instr(opcode, 1, offset)
            case Opcode.LOOP:
                return self.jmp_instr(opcode, -1, offset)
            case _:
                print(f'{offset:04} {opcode}')
                return offset + 1

    def const_instr(self, opcode: Opcode, offset):
        idx   = self.code[offset + 1]
        value = "'" + str(self.constants[idx]) + "'"
        print(f'{offset:04} {opcode} {idx} {value}')
        return offset + 2

    def byte_instr(self, opcode: Opcode, offset):
        slot  = self.code[offset + 1]
        print(f'{offset:04} {opcode} {slot}')
        return offset + 2

    def jmp_instr(self, opcode: Opcode, sign, offset):
        jmp  = self.code[offset + 1] << 8
        jmp |= self.code[offset + 2] << 0
        print(f'{offset:04} {opcode} -> {offset + 3 + sign * jmp}')
        return offset + 3

class Compiler:
    def __init__(self, loglvl=LogLevel.ERROR):
        self.funcs   = {'main' : Function()}
        self.func    = self.funcs['main']
        self.log_lvl = loglvl

    def visit(self, node):
        name = node.__class__.__name__
        visitor = getattr(self, 'visit_' + name.lower(), None)
        if visitor:
            self.log_node(node)
            visitor(node)
        else:
            raise RuntimeError(f'visit_{name.lower()} has no implementation.')

    def visit_module(self, node: ast.Module):
        for stmt in node.body:
            self.visit(stmt)

    def visit_expr(self, node: ast.Expr):
        self.visit(node.value)
        self.func.emit_byte(Opcode.POP.value)

    def visit_constant(self, node: ast.Constant):
        self.func.emit_byte(Opcode.CONST.value)
        self.func.emit_byte(self.make_const(node.value))

    def visit_compare(self, node: ast.Compare):
        assert len(node.comparators) == 1, 'only a single comparison operand allowed'
        assert len(node.ops) == 1, 'only a single comparison operator allowed'
        self.visit(node.left)
        self.visit(node.comparators[0])
        self.visit(node.ops[0])

    def visit_boolop(self, node: ast.BoolOp):
        self.visit(node.values[0])
        for value in node.values[1:]:
            self.visit(value)
            self.visit(node.op)

    def visit_pass(self, _):
        pass

    def visit_assign(self, node: ast.Assign):
        for target in node.targets:
            match target:
                case ast.Name():
                    self.visit(node.value)
                    self.visit(target)
                case _:
                    assert False, f'unhandled target {target} in Assign'

    def visit_name(self, node: ast.Name):
        match node.ctx:
            case ast.Load():
                self.func.emit_byte(Opcode.GET_VAR.value)
                if node.id not in self.func.locals:
                    raise RuntimeError(f'local variable "{node.id}" was never defined')
                self.func.emit_byte(self.func.locals.index(node.id))
            case ast.Store():
                self.func.emit_byte(Opcode.SET_VAR.value)
                if node.id not in self.func.locals:
                    self.func.locals.append(node.id)
                    self.func.emit_byte(len(self.func.locals) - 1)
                else:
                    self.func.emit_byte(self.func.locals.index(node.id))
            case ast.Del():
                if self.log_lvl.value <= LogLevel.ERROR.value:
                    print('WARNING - ast.Del() currently does nothing in locals')

    def visit_functiondef(self, node: ast.FunctionDef):
        self.func.code.append(Opcode.CONST.value)
        self.func.code.append(self.make_const(node.name))

        self.funcs[node.name] = Function(len(node.args.args))
        tmp                   = self.func
        self.func             = self.funcs[node.name]

        for a in node.args.args:
            self.func.locals.append(a.arg)
        for stmt in node.body:
            self.visit(stmt)

        self.func = tmp

    def visit_return(self, node: ast.Return):
        self.visit(node.value)
        self.func.emit_byte(Opcode.RET.value)

    def visit_binop(self, node: ast.BinOp):
        self.visit(node.left)
        self.visit(node.right)
        self.visit(node.op)

    def visit_add(self, _):
        self.func.emit_byte(Opcode.ADD.value)

    def visit_sub(self, _):
        self.func.emit_byte(Opcode.SUB.value)

    def visit_and(self, _):
        self.func.emit_byte(Opcode.AND.value)

    def visit_bitand(self, _):
        self.func.emit_byte(Opcode.BIT_AND.value)

    def visit_or(self, _):
        self.func.emit_byte(Opcode.OR.value)

    def visit_bitor(self, _):
        self.func.emit_byte(Opcode.BIT_OR.value)

    def visit_bitxor(self, _):
        self.func.emit_byte(Opcode.BIT_XOR.value)

    def visit_mult(self, _):
        self.func.emit_byte(Opcode.MULT.value)

    def visit_div(self, _):
        self.func.emit_byte(Opcode.DIV.value)

    def visit_lt(self, _):
        self.func.emit_byte(Opcode.LT.value)

    def visit_lte(self, _):
        self.func.emit_byte(Opcode.LTE.value)

    def visit_gt(self, _):
        self.func.emit_byte(Opcode.GT.value)

    def visit_gte(self, _):
        self.func.emit_byte(Opcode.GTE.value)

    def visit_eq(self, _):
        self.func.emit_byte(Opcode.EQ.value)

    def visit_noteq(self, _):
        self.func.emit_byte(Opcode.NOT_EQ.value)

    def visit_unaryop(self, node: ast.UnaryOp):
        self.visit(node.operand)
        match node.op:
            case ast.USub():
                self.func.emit_byte(Opcode.NEG.value)
            case ast.Invert():
                self.func.emit_byte(Opcode.INVERT.value)
            case ast.Not():
                self.func.emit_byte(Opcode.NOT.value)
            case ast.UAdd():
                self.func.emit_byte(Opcode.UADD.value)

    def visit_while(self, node: ast.While):
        loop_start = len(self.func.code)
        self.visit(node.test)

        exit_jmp = self.emit_jmp(Opcode.JMP_IF_FALSE.value)
        self.func.emit_byte(Opcode.POP.value)
        for stmt in node.body:
            self.visit(stmt)
        self.emit_loop(loop_start)
        self.patch_jmp(exit_jmp)
        self.func.emit_byte(Opcode.POP.value)

    def visit_if(self, node: ast.If):
        self.visit(node.test)

        then_jmp = self.emit_jmp(Opcode.JMP_IF_FALSE.value)
        self.func.emit_byte(Opcode.POP.value)
        for stmt in node.body:
            self.visit(stmt)

        else_jmp = self.emit_jmp(Opcode.JMP.value)
        self.patch_jmp(then_jmp)
        self.func.emit_byte(Opcode.POP.value)
        for stmt in node.orelse:
            self.visit(stmt)
        self.patch_jmp(else_jmp)

    def visit_call(self, node: ast.Call):
        for arg in node.args:
            self.visit(arg)
        match node.func:
            case ast.Name():
                if node.func.id == 'print':
                    self.func.emit_byte(Opcode.PRINT.value)
                    self.func.emit_byte(Opcode.NIL.value)
                else:
                    self.func.emit_byte(Opcode.CALL.value)
                    if node.func.id in self.funcs:
                        self.func.emit_byte(self.funcs[node.func.id].arity)
                    else:
                        raise RuntimeError(f'{node.func.id} not found')

    def visit_assert(self, node: ast.Assert):
        self.visit(node.test)
        self.func.emit_byte(Opcode.ASSERT.value)

    def log_node(self, node):
        match self.log_lvl:
            case LogLevel.DEBUG:
                print(ast.dump(node))
            case LogLevel.INFO:
                print(str(node).split(' ')[0][5:])
            case _:
                pass

    def make_const(self, value):
        assert len(self.func.constants) < 255, 'exceeded constants for function'
        self.func.constants.append(value)
        return len(self.func.constants) - 1

    def emit_jmp(self, opcode):
        self.func.emit_byte(opcode)
        self.func.emit_byte(0xff)
        self.func.emit_byte(0xff)
        return len(self.func.code) - 2

    def patch_jmp(self, offset):
        jmp = len(self.func.code) - offset - 2
        if jmp > 65535:
            raise RuntimeError('too much code to jump over')
        self.func.code[offset + 0] = (jmp >> 8) & 0xff
        self.func.code[offset + 1] = (jmp >> 0) & 0xff

    def emit_loop(self, loop_start):
        self.func.emit_byte(Opcode.LOOP.value)
        offset = len(self.func.code) - loop_start + 2
        if offset > 65535:
            raise RuntimeError('loop body too large')
        self.func.emit_byte((offset >> 8) & 0xff)
        self.func.emit_byte((offset >> 0) & 0xff)

class Result(Enum):
    OK          = 0
    COMPILE_ERR = 1
    RUNTIME_ERR = 2

class Frame:
    def __init__(self, func, ip, sp):
        self.func: Function = func
        self.ip             = ip
        self.sp             = sp

    def get_slot(self, stack, idx):
        return stack[idx + self.sp]

    def set_slot(self, stack, idx, val):
        stack[idx + self.sp] = val

    def __str__(self):
        return f'ip {self.ip}, sp {self.sp}'

class VM:
    def __init__(self, funcs, loglvl=LogLevel.ERROR):
        self.stack   = []
        self.funcs   = funcs
        self.frame   = Frame(self.funcs['main'], 0, 0)
        self.frames  = [self.frame]
        self.log_lvl = loglvl
        self.limit   = 500 # TODO remove

    def read_byte(self, func: Function):
        byte = func.code[self.frame.ip]
        self.frame.ip += 1
        return byte

    def read_short(self, func: Function):
        short  = func.code[self.frame.ip] << 8
        self.frame.ip += 1
        short |= func.code[self.frame.ip]
        self.frame.ip += 1
        return short

    def interpret(self):
        instr_count = 0 # TODO remove
        while self.frame.ip < len(self.frame.func.code):
            instr_count += 1 # TODO remove
            if instr_count > self.limit: # TODO remove
                print("instruction limit reached, possibly bugs")
                return Result.RUNTIME_ERR
            if self.log_lvl == LogLevel.DEBUG:
                for i, obj in enumerate(self.stack):
                    if i == len(self.stack) - 1:
                        print(f'[{obj}]')
                    else:
                        print(f'[{obj}]', end='')
                self.frame.func.disass_instr(self.frame.ip)

            opcode = Opcode(self.read_byte(self.frame.func))
            match opcode:
                case Opcode.RET:
                    return Result.OK
                case Opcode.CONST:
                    idx   = self.read_byte(self.frame.func)
                    value = self.frame.func.constants[idx]
                    self.stack.append(value)
                    continue
                case Opcode.GET_VAR:
                    idx   = self.read_byte(self.frame.func)
                    value = self.frame.get_slot(self.stack, idx)
                    self.stack.append(value)
                    continue
                case Opcode.SET_VAR:
                    idx = self.read_byte(self.frame.func)
                    if idx + self.frame.sp + 1 != len(self.stack):
                        val = self.stack.pop()
                    else:
                        val = self.stack[-1]
                    self.frame.set_slot(self.stack, idx, val)
                    continue
                case Opcode.PRINT:
                    print(self.stack.pop())
                    continue
                case Opcode.NEG:
                    a = self.stack.pop()
                    self.stack.append(-a)
                    continue
                case Opcode.POP:
                    self.stack.pop()
                    continue
                case Opcode.NIL:
                    self.stack.append(0)
                    continue
                case Opcode.TRUE:
                    self.stack.append(True)
                    continue
                case Opcode.FALSE:
                    self.stack.append(False)
                    continue
                case Opcode.ASSERT:
                    if not self.stack.pop():
                        print('assertion failure')
                    continue
                case Opcode.JMP_IF_FALSE:
                    offset = self.read_short(self.frame.func)
                    if (not self.stack[-1]):
                        self.frame.ip += offset
                    continue
                case Opcode.JMP:
                    offset = self.read_short(self.frame.func)
                    self.frame.ip += offset
                    continue
                case Opcode.LOOP:
                    offset = self.read_short(self.frame.func)
                    self.frame.ip -= offset
                    continue
                case Opcode.CALL:
                    arg_count = self.read_byte(self.frame.func)
                    name = self.stack[-arg_count - 1]
                    if name in self.funcs:
                        func = self.funcs[name]
                        if func.arity != arg_count:
                            raise RuntimeError(f'"{name}" arity {func.arity}, args {arg_count}')
                        else:
                            self.frame = Frame(func, 0, len(self.stack) - arg_count)
                            self.frames.append(self.frame)
                    else:
                        raise RuntimeError(f'"{func.name}" arity {func.arity}, args {arg_count}')

                case _:
                    if opcode in binops:
                        b = self.stack.pop()
                        a = self.stack.pop()
                        result = binops[opcode](a, b)
                        self.stack.append(result)
                        continue
                    else:
                        print(f'{opcode} unhandled')
                        return Result.RUNTIME_ERR
        return Result.OK

def main():
    parser = argparse.ArgumentParser(
        prog='python3 pyvm.py',
        description='inputs python source and runs on a custom stack machine'
    )
    log_lvls = 'log levels DEBUG(0) INFO(1) ERROR(2)'
    parser.add_argument('-l', '--log', type=int, default=LogLevel.ERROR.value, help=log_lvls)
    parser.add_argument('file', help='input a python file (e.g. test.py)')
    args = parser.parse_args()

    match args.log:
        case LogLevel.DEBUG.value:
            log_lvl = LogLevel.DEBUG
        case LogLevel.INFO.value:
            log_lvl = LogLevel.INFO
        case LogLevel.ERROR.value:
            log_lvl = LogLevel.ERROR
        case _:
            assert False, f'-l{args.log}?, {log_lvls}'

    def print_section(name):
        print('-' * (len(str(name)) + 4))
        print('| ' + str(name) + ' |')
        print('-' * (len(str(name)) + 4))

    with open(args.file) as file:
        if log_lvl.value <= LogLevel.INFO.value:
            print_section(log_lvl)
            nodes_visited = 'Nodes visited'
            if log_lvl.value <= LogLevel.DEBUG.value:
                nodes_visited += ' (With AST Info)'
            print_section(nodes_visited)

        src = file.read()
        node = ast.parse(src, filename=args.file)
        compiler = Compiler(loglvl=log_lvl)
        compiler.visit(node)

        if log_lvl.value <= LogLevel.INFO.value:
            print_section('Input Progam')
            print(src.strip())
            print_section('Disassembly')
            print(f'main:')
            compiler.funcs['main'].disass()
            for name, func in compiler.funcs.items():
                if name == 'main':
                    continue
                print(f'{name}:')
                func.disass()

        if log_lvl.value <= LogLevel.INFO.value:
            vm_title = 'VM'
            if log_lvl.value <= LogLevel.DEBUG.value:
                vm_title += ' (Stack Trace Enabled)'
            print_section(vm_title)

        vm = VM(compiler.funcs, loglvl=log_lvl)
        while True:
            res = vm.interpret()
            if log_lvl.value <= LogLevel.DEBUG.value:
                print_section('Stack')
                print(vm.stack)
            match res:
                case Result.OK:
                    break
                case Result.COMPILE_ERR:
                    print('COMPILER ERROR')
                    return
                case Result.RUNTIME_ERR:
                    print('RUNTIME ERROR')
                    return
                case _:
                    print(f'UNKNOWN ERROR {res}')
                    return

if __name__ == '__main__':
    main()
