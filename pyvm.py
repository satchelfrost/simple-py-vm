import ast
from enum import Enum
import argparse

class LogLevel(Enum):
    DEBUG = 0
    INFO  = 1
    ERROR = 2

class Opcode(Enum):
    ADD           = 0
    SUB           = 1
    MULT          = 2
    DIV           = 3
    AND           = 4
    BIT_AND       = 5
    OR            = 6
    BIT_OR        = 7
    BIT_XOR       = 8
    LT            = 9
    LTE           = 10
    GT            = 11
    GTE           = 12
    EQ            = 13
    NOT_EQ        = 14
    INVERT        = 15
    NOT           = 16
    UADD          = 17
    NEG           = 18
    RET           = 19
    CONST         = 20
    PRINT         = 21
    NIL           = 22
    GET_GLOBAL    = 23
    SET_GLOBAL    = 24
    GET_LOCAL     = 25
    SET_LOCAL     = 26
    POP           = 27
    TRUE          = 28
    FALSE         = 29
    ASSERT        = 30
    JMP           = 31
    JMP_IF_FALSE  = 32
    LOOP          = 33
    CALL          = 34

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

class Chunk:
    def __init__(self):
        self.code      = bytearray()
        self.constants = []

    def disass(self):
        offset = 0
        while offset < len(self.code):
            offset = self.disass_instr(offset)

    def disass_instr(self, offset):
        opcode = Opcode(self.code[offset])
        match opcode:
            case Opcode.CONST:
                return self.const_instr(opcode, offset)
            case Opcode.SET_GLOBAL:
                return self.const_instr(opcode, offset)
            case Opcode.GET_GLOBAL:
                return self.const_instr(opcode, offset)
            case Opcode.SET_LOCAL:
                return self.byte_instr(opcode, offset)
            case Opcode.GET_LOCAL:
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
        self.chunks       = [Chunk()]
        self.chunk        = self.chunks[0]
        self.log_lvl      = loglvl
        self.globals      = {}
        self.locals       = []
        self.global_scope = False
        self.arg_count    = 0 # TODO: may need to reset


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
        self.chunk.code.append(Opcode.POP.value)

    def visit_constant(self, node: ast.Constant):
        self.chunk.code.append(Opcode.CONST.value)
        idx = self.make_const(node.value)
        self.chunk.code.append(idx)

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
        if self.global_scope:
            self.match_global(node.ctx, node.id)
        else:
            self.match_local(node.ctx, node.id)

    def match_local(self, ctx, name):
        match ctx:
            case ast.Load():
                self.chunk.code.append(Opcode.GET_LOCAL.value)
                if name not in self.locals:
                    raise RuntimeError(f'local variable "{name}" was never defined')
                self.chunk.code.append(self.locals.index(name))
            case ast.Store():
                self.chunk.code.append(Opcode.SET_LOCAL.value)
                if name not in self.locals:
                    self.locals.append(name)
                    self.chunk.code.append(len(self.locals) - 1)
                else:
                    self.chunk.code.append(self.locals.index(name))
            case ast.Del():
                if self.log_lvl.value <= LogLevel.ERROR.value:
                    print('WARNING - ast.Del() currently does nothing in locals')

    def match_global(self, ctx, name):
        match ctx:
            case ast.Load():
                self.chunk.code.append(Opcode.GET_GLOBAL.value)
                if name not in self.globals:
                    raise RuntimeError(f'variable "{name}" was never defined')
                self.chunk.code.append(self.globals[name])
            case ast.Store():
                self.chunk.code.append(Opcode.SET_GLOBAL.value)
                if name not in self.globals:
                    self.globals[name] = self.make_const(name)
                self.chunk.code.append(self.globals[name])
            case ast.Del():
                if self.log_lvl.value <= LogLevel.ERROR.value:
                    print('WARNING - ast.Del() currently does nothing in globals')

    def visit_functiondef(self, node: ast.FunctionDef):
        self.begin_scope()
        self.arg_count = len(node.args.args)
        for a in node.args.args:
            self.locals.append(a.arg)
        for stmt in node.body:
            self.visit(stmt)
        self.end_scope()

        self.chunk.code.append(Opcode.SET_GLOBAL.value)
        self.globals[node.name] = self.make_const(node.name)
        self.chunk.code.append(self.globals[node.name])

    def visit_return(self, node: ast.Return):
        self.visit(node.value)
        self.chunk.code.append(Opcode.RET.value)

    def visit_binop(self, node: ast.BinOp):
        self.visit(node.left)
        self.visit(node.right)
        self.visit(node.op)

    def visit_add(self, _):
        self.chunk.code.append(Opcode.ADD.value)

    def visit_sub(self, _):
        self.chunk.code.append(Opcode.SUB.value)

    def visit_and(self, _):
        self.chunk.code.append(Opcode.AND.value)

    def visit_bitand(self, _):
        self.chunk.code.append(Opcode.BIT_AND.value)

    def visit_or(self, _):
        self.chunk.code.append(Opcode.OR.value)

    def visit_bitor(self, _):
        self.chunk.code.append(Opcode.BIT_OR.value)

    def visit_bitxor(self, _):
        self.chunk.code.append(Opcode.BIT_XOR.value)

    def visit_mult(self, _):
        self.chunk.code.append(Opcode.MULT.value)

    def visit_div(self, _):
        self.chunk.code.append(Opcode.DIV.value)

    def visit_lt(self, _):
        self.chunk.code.append(Opcode.LT.value)

    def visit_lte(self, _):
        self.chunk.code.append(Opcode.LTE.value)

    def visit_gt(self, _):
        self.chunk.code.append(Opcode.GT.value)

    def visit_gte(self, _):
        self.chunk.code.append(Opcode.GTE.value)

    def visit_eq(self, _):
        self.chunk.code.append(Opcode.EQ.value)

    def visit_noteq(self, _):
        self.chunk.code.append(Opcode.NOT_EQ.value)

    def visit_unaryop(self, node: ast.UnaryOp):
        self.visit(node.operand)
        match node.op:
            case ast.USub():
                self.chunk.code.append(Opcode.NEG.value)
            case ast.Invert():
                self.chunk.code.append(Opcode.INVERT.value)
            case ast.Not():
                self.chunk.code.append(Opcode.NOT.value)
            case ast.UAdd():
                self.chunk.code.append(Opcode.UADD.value)

    def visit_while(self, node: ast.While):
        loop_start = len(self.chunk.code)
        self.visit(node.test)

        exit_jmp = self.emit_jmp(Opcode.JMP_IF_FALSE.value)
        self.chunk.code.append(Opcode.POP.value)
        for stmt in node.body:
            self.visit(stmt)
        self.emit_loop(loop_start)
        self.patch_jmp(exit_jmp)
        self.chunk.code.append(Opcode.POP.value)

    def visit_if(self, node: ast.If):
        self.visit(node.test)

        then_jmp = self.emit_jmp(Opcode.JMP_IF_FALSE.value)
        self.chunk.code.append(Opcode.POP.value)
        for stmt in node.body:
            self.visit(stmt)

        else_jmp = self.emit_jmp(Opcode.JMP.value)
        self.patch_jmp(then_jmp)
        self.chunk.code.append(Opcode.POP.value)
        for stmt in node.orelse:
            self.visit(stmt)
        self.patch_jmp(else_jmp)

    def visit_call(self, node: ast.Call): # TODO still incomplete
        for arg in node.args:
            self.visit(arg)
        match node.func:
            case ast.Name():
                if node.func.id == 'print':
                    self.chunk.code.append(Opcode.PRINT.value)
                    self.chunk.code.append(Opcode.NIL.value)
                else:
                    self.chunk.code.append(Opcode.CALL.value)
                    self.chunk.code.append(self.arg_count)

    def visit_assert(self, node: ast.Assert):
        self.visit(node.test)
        self.chunk.code.append(Opcode.ASSERT.value)

    def log_node(self, node):
        match self.log_lvl:
            case LogLevel.DEBUG:
                print(ast.dump(node))
            case LogLevel.INFO:
                print(str(node).split(' ')[0][5:])
            case _:
                pass

    def make_const(self, value):
        assert len(self.chunk.constants) < 255, 'exceeded constants for chunk'
        self.chunk.constants.append(value)
        return len(self.chunk.constants) - 1

    def emit_jmp(self, opcode):
        self.chunk.code.append(opcode)
        self.chunk.code.append(0xff)
        self.chunk.code.append(0xff)
        return len(self.chunk.code) - 2

    def patch_jmp(self, offset):
        jmp = len(self.chunk.code) - offset - 2
        if jmp > 65535:
            raise RuntimeError('too much code to jump over')
        self.chunk.code[offset + 0] = (jmp >> 8) & 0xff
        self.chunk.code[offset + 1] = (jmp >> 0) & 0xff

    def emit_loop(self, loop_start):
        self.chunk.code.append(Opcode.LOOP.value)
        offset = len(self.chunk.code) - loop_start + 2
        if offset > 65535:
            raise RuntimeError('loop body too large')
        self.chunk.code.append((offset >> 8) & 0xff)
        self.chunk.code.append((offset >> 0) & 0xff)

    def begin_scope(self):
        self.global_scope = False

    def end_scope(self):
        self.global_scope = True
        for _ in self.locals:
            self.chunk.code.append(Opcode.POP.value)
            self.locals.pop()

class Result(Enum):
    OK          = 0
    COMPILE_ERR = 1
    RUNTIME_ERR = 2

class VM:
    def __init__(self, loglvl=LogLevel.ERROR):
        self.ip      = 0
        self.stack   = []
        self.chunk   = None
        self.log_lvl = loglvl
        self.globals = {}
        self.limit   = 500

    def read_byte(self, chunk):
        byte = chunk.code[self.ip]
        self.ip += 1
        return byte

    def read_short(self, chunk):
        short  = chunk.code[self.ip] << 8
        self.ip += 1
        short |= chunk.code[self.ip]
        self.ip += 1
        return short

    def interpret(self, chunk : Chunk):
        self.chunk = chunk
        instr_count = 0
        while self.ip < len(chunk.code):
            instr_count += 1
            if instr_count > self.limit:
                print("instruction limit reached, possibly bugs")
                return Result.RUNTIME_ERR
            if self.log_lvl == LogLevel.DEBUG:
                for i, obj in enumerate(self.stack):
                    if i == len(self.stack) - 1:
                        print(f'[{obj}]')
                    else:
                        print(f'[{obj}]', end='')
                chunk.disass_instr(self.ip)

            opcode = Opcode(self.read_byte(chunk))
            match opcode:
                case Opcode.RET:
                    return Result.OK
                case Opcode.CONST:
                    idx   = self.read_byte(chunk)
                    value = chunk.constants[idx]
                    self.stack.append(value)
                    continue
                case Opcode.GET_GLOBAL:
                    idx   = self.read_byte(chunk)
                    name  = chunk.constants[idx]
                    value = self.globals[name]
                    self.stack.append(value)
                    continue
                case Opcode.SET_GLOBAL:
                    idx  = self.read_byte(chunk)
                    name = chunk.constants[idx]
                    self.globals[name] = self.stack.pop()
                    continue
                case Opcode.GET_LOCAL:
                    idx   = self.read_byte(chunk)
                    value = self.stack[idx]
                    self.stack.append(value)
                    continue
                case Opcode.SET_LOCAL:
                    idx = self.read_byte(chunk)
                    if idx + 1 != len(self.stack):
                        val = self.stack.pop()
                    else:
                        val = self.stack[-1]
                    self.stack[idx] = val
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
                    offset = self.read_short(chunk)
                    if (not self.stack[-1]):
                        self.ip += offset
                    continue
                case Opcode.JMP:
                    offset = self.read_short(chunk)
                    self.ip += offset
                    continue
                case Opcode.LOOP:
                    offset = self.read_short(chunk)
                    self.ip -= offset
                    continue
                case Opcode.CALL:
                    arg_count = self.read_byte(chunk)
                    print(f'arg_count {arg_count}, stack {self.stack}')
                    raise RuntimeError('STOPPING')
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
            for chunk in compiler.chunks:
                chunk.disass()

        if log_lvl.value <= LogLevel.INFO.value:
            vm_title = 'VM'
            if log_lvl.value <= LogLevel.DEBUG.value:
                vm_title += ' (Stack Trace Enabled)'
            print_section(vm_title)

        vm = VM(loglvl=log_lvl)
        while True:
            res = vm.interpret(compiler.chunk)
            if log_lvl.value <= LogLevel.DEBUG.value:
                print_section(f'Globals')
                print(vm.globals)
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
