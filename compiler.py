import ast
from enum import Enum

class LogLevel(Enum):
    DEBUG   = 0
    INFO    = 1
    WARNING = 2
    ERROR   = 3

class Opcode(Enum):
    ADD        = 0
    SUB        = 1
    MULT       = 2
    DIV        = 3
    AND        = 4
    BIT_AND    = 5
    OR         = 6
    BIT_OR     = 7
    BIT_XOR    = 8
    LT         = 9
    LTE        = 10
    GT         = 11
    GTE        = 12
    EQ         = 13
    NOT_EQ     = 14
    INVERT     = 15
    NOT        = 16
    UADD       = 17
    NEG        = 18
    RET        = 19
    CONST      = 20
    PRINT      = 21
    NIL        = 22
    GET_GLOBAL = 23
    SET_GLOBAL = 24
    DEF_GLOBAL = 25
    POP        = 26

opcode_to_op = {
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
                idx   = self.code[offset + 1]
                value = self.constants[idx]
                print(f'{offset:04} {opcode} {value}')
                return offset + 2
            case Opcode.DEF_GLOBAL:
                idx   = self.code[offset + 1]
                value = self.constants[idx]
                print(f'{offset:04} {opcode} {value}')
                return offset + 2
            case _:
                print(f'{offset:04} {opcode}')
                return offset + 1

class Compiler:
    def __init__(self, loglvl=LogLevel.WARNING):
        self.chunks  = [Chunk()]
        self.chunk   = self.chunks[0]
        self.log_lvl = loglvl
        self.globals = set()

    def log_node(self, node):
        match self.log_lvl:
            case LogLevel.DEBUG:
                print(ast.dump(node))
            case LogLevel.INFO:
                print(str(node).split(' ')[0][1:])
            case _:
                pass

    def visit(self, node):
        name = node.__class__.__name__
        visitor = getattr(self, 'visit_' + name, None)
        if visitor:
            visitor(node)
        else:
            raise RuntimeError(f'visit_{name} has no implementation. {ast.dump(node)}')

    def visit_Module(self, node: ast.Module):
        self.log_node(node)
        for stmt in node.body:
            self.visit(stmt)

    def visit_Expr(self, node: ast.Expr):
        self.log_node(node)
        self.visit(node.value)
        self.chunk.code.append(Opcode.POP.value)

    def visit_Constant(self, node: ast.Constant):
        self.log_node(node)
        assert len(self.chunk.constants) < 256, 'exceeded constants for chunk'
        self.chunk.constants.append(node.value)
        self.chunk.code.append(Opcode.CONST.value)
        self.chunk.code.append(len(self.chunk.constants) - 1)

    def visit_Compare(self, node: ast.Compare):
        self.log_node(node)
        assert len(node.comparators) == 1, 'only a single comparison operand allowed'
        assert len(node.ops) == 1, 'only a single comparison operator allowed'
        self.visit(node.left)
        self.visit(node.comparators[0])
        self.visit(node.ops[0])

    def visit_Assign(self, node: ast.Assign):
        self.log_node(node)
        for target in node.targets:
            match target:
                case ast.Name():
                    self.visit(node.value)
                    self.visit(target)
                    assert len(self.chunk.constants) < 256, 'exceeded constants for chunk'
                    self.chunk.constants.append(target.id)
                    self.chunk.code.append(len(self.chunk.constants) - 1)
                case _:
                    assert False, f'unhandled target {target} in Assign'

    def visit_Name(self, node: ast.Name):
        self.log_node(node)
        match node.ctx:
            case ast.Load():
                self.chunk.code.append(Opcode.GET_GLOBAL.value)
            case ast.Store():
                if node.id in self.globals:
                    self.chunk.code.append(Opcode.SET_GLOBAL.value)
                else:
                    self.globals.add(node.id)
                    self.chunk.code.append(Opcode.DEF_GLOBAL.value)
            case ast.Del():
                if self.log_lvl.value <= LogLevel.WARNING.value:
                    print('warning ast.Del() currently does nothing')

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.log_node(node)
        assert False, "FunctionDef has no implementation" # TODO

    def visit_Return(self, node: ast.Return):
        self.visit(node.value)
        self.chunk.code.append(Opcode.RET.value)

    def visit_BinOp(self, node: ast.BinOp):
        self.log_node(node)
        self.visit(node.left)
        self.visit(node.right)
        self.visit(node.op)

    def visit_Add(self, node: ast.Add):
        self.log_node(node)
        self.chunk.code.append(Opcode.ADD.value)

    def visit_Sub(self, node: ast.Sub):
        self.log_node(node)
        self.chunk.code.append(Opcode.SUB.value)

    def visit_And(self, node: ast.And):
        self.log_node(node)
        self.chunk.code.append(Opcode.AND.value)

    def visit_BitAnd(self, node: ast.BitAnd):
        self.log_node(node)
        self.chunk.code.append(Opcode.BIT_AND.value)

    def visit_Or(self, node: ast.Or):
        self.log_node(node)
        self.chunk.code.append(Opcode.OR.value)

    def visit_BitOr(self, node: ast.BitOr):
        self.log_node(node)
        self.chunk.code.append(Opcode.BIT_OR.value)

    def visit_BitXor(self, node: ast.BitXor):
        self.log_node(node)
        self.chunk.code.append(Opcode.BIT_XOR.value)

    def visit_Mult(self, node: ast.Mult):
        self.log_node(node)
        self.chunk.code.append(Opcode.MULT.value)

    def visit_Div(self, node: ast.Div):
        self.log_node(node)
        self.chunk.code.append(Opcode.DIV.value)

    def visit_Lt(self, node: ast.Lt):
        self.log_node(node)
        self.chunk.code.append(Opcode.LT.value)

    def visit_LtE(self, node: ast.LtE):
        self.log_node(node)
        self.chunk.code.append(Opcode.LTE.value)

    def visit_Gt(self, node: ast.Gt):
        self.log_node(node)
        self.chunk.code.append(Opcode.GT.value)

    def visit_GtE(self, node: ast.GtE):
        self.log_node(node)
        self.chunk.code.append(Opcode.GTE.value)

    def visit_Eq(self, node: ast.Eq):
        self.log_node(node)
        self.chunk.code.append(Opcode.EQ.value)

    def visit_NotEq(self, node: ast.NotEq):
        self.log_node(node)
        self.chunk.code.append(Opcode.NOT_EQ.value)

    def visit_UnaryOp(self, node: ast.UnaryOp):
        self.log_node(node)
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

    def visit_While(self, node: ast.While):
        self.log_node(node)
        assert False, "While has no implementation" # TODO

    def visit_If(self, node: ast.If):
        self.log_node(node)
        assert False, "If has no implementation" # TODO

    def visit_Call(self, node: ast.Call): # TODO still incomplete
        self.log_node(node)
        for arg in node.args:
            self.visit(arg)
        match node.func:
            case ast.Name():
                if node.func.id == 'print':
                    self.chunk.code.append(Opcode.PRINT.value)
                    self.chunk.code.append(Opcode.NIL.value)

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

    def read_byte(self, chunk):
        byte = chunk.code[self.ip]
        self.ip += 1
        return byte

    def interpret(self, chunk : Chunk):
        self.chunk = chunk
        while self.ip < len(chunk.code):
            if self.log_lvl == LogLevel.DEBUG:
                for obj in self.stack:
                    print(f'[{obj}]')
                chunk.disass_instr(self.ip)

            opcode = Opcode(self.read_byte(chunk))

            # handle binary operations
            if opcode.value <= Opcode.NOT_EQ.value:
                b = self.stack.pop()
                a = self.stack.pop()
                result = opcode_to_op[opcode](a, b)
                self.stack.append(result)
                continue

            match opcode:
                case Opcode.RET:
                    return Result.OK
                case Opcode.CONST:
                    idx   = self.read_byte(chunk)
                    value = chunk.constants[idx]
                    self.stack.append(value)
                    continue
                case Opcode.DEF_GLOBAL:
                    idx  = self.read_byte(chunk)
                    name = chunk.constants[idx]
                    self.globals[name] = self.stack.pop()
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
                case _:
                    print(f'{opcode} unhandled')
                    return Result.RUNTIME_ERR
        return Result.OK

log_lvl = LogLevel.DEBUG
def main():
    def print_section(name):
        print('-' * (len(str(name)) + 4))
        print('| ' + str(name) + ' |')
        print('-' * (len(str(name)) + 4))

    file_name = 'tests/compare.py'
    with open(file_name) as file:
        if log_lvl.value <= LogLevel.INFO.value:
            print_section(log_lvl)
        if log_lvl.value <= LogLevel.INFO.value:
            print_section('Nodes visited')

        src = file.read()
        node = ast.parse(src, filename=file_name)
        compiler = Compiler(loglvl=log_lvl)
        compiler.visit(node)

        if log_lvl.value <= LogLevel.INFO.value:
            print_section('Dissassembly')
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
                    print('compiler error')
                    return
                case Result.RUNTIME_ERR:
                    print('runtime error')
                    return
                case _:
                    print(f'unknown error {res}')
                    return

if __name__ == '__main__':
    main()
