import ast
from enum import Enum

class LogLevel(Enum):
    NONE    = 0
    VERBOSE = 1
    INFO    = 2
    WARNING = 3
    ERROR   = 4

class Opcode(Enum):
    ADD     = 0
    SUB     = 1
    MULT    = 2
    DIV     = 3
    AND     = 4
    BIT_AND = 5
    OR      = 6
    BIT_OR  = 7
    BIT_XOR = 8
    LT      = 9
    LTE     = 10
    GT      = 11
    GTE     = 12
    EQ      = 13
    NOT_EQ  = 14
    INVERT  = 15
    NOT     = 16
    UADD    = 17
    NEG     = 18
    RET     = 19
    CONST   = 20

class Chunk:
    def __init__(self):
        self.code = bytearray()
        self.constants = []
        self.offset = 0

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
            case Opcode.NEG:
                return self.deflt_disass(offset, opcode)
            case Opcode.ADD:
                return self.deflt_disass(offset, opcode)
            case Opcode.SUB:
                return self.deflt_disass(offset, opcode)
            case Opcode.MULT:
                return self.deflt_disass(offset, opcode)
            case Opcode.DIV:
                return self.deflt_disass(offset, opcode)
            case Opcode.AND:
                return self.deflt_disass(offset, opcode)
            case Opcode.BIT_AND:
                return self.deflt_disass(offset, opcode)
            case Opcode.OR:
                return self.deflt_disass(offset, opcode)
            case Opcode.BIT_OR:
                return self.deflt_disass(offset, opcode)
            case Opcode.BIT_XOR:
                return self.deflt_disass(offset, opcode)
            case Opcode.LT:
                return self.deflt_disass(offset, opcode)
            case Opcode.LTE:
                return self.deflt_disass(offset, opcode)
            case Opcode.GT:
                return self.deflt_disass(offset, opcode)
            case Opcode.GTE:
                return self.deflt_disass(offset, opcode)
            case Opcode.EQ:
                return self.deflt_disass(offset, opcode)
            case Opcode.NOT_EQ:
                return self.deflt_disass(offset, opcode)
            case Opcode.RET:
                return self.deflt_disass(offset, opcode)
            case _:
                print(f'{offset:04} {opcode} [WARNING] - unknown opcode')
                return offset + 1

    def deflt_disass(self, offset: int, opcode: Opcode):
        print(f'{offset:04} | {opcode}')
        return offset + 1

class Compiler:
    def __init__(self, loglvl=LogLevel.NONE):
        self.chunks  = [Chunk()]
        self.chunk   = self.chunks[0]
        self.log_lvl = loglvl

    def log_node(self, node):
        if self.log_lvl.value > 0:
            match self.log_lvl:
                case LogLevel.VERBOSE:
                    print(ast.dump(node))
                case _:
                    print(str(node).split(' ')[0][1:])

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

    def visit_Name(self, node: ast.Name):
        self.log_node(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.log_node(node)

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

    def visit_While(self, node: ast.For):
        self.log_node(node)

    def visit_If(self, node: ast.If):
        self.log_node(node)

    def visit_Call(self, node: ast.Call):
        self.log_node(node)

class InterpretResult(Enum):
    OK          = 0
    COMPILE_ERR = 1
    RUNTIME_ERR = 2
    HALT        = 3

class VM:
    def __init__(self):
        self.ip    = 0
        self.stack = []
        self.chunk = None

    def read_byte(self, chunk):
        byte = chunk.code[self.ip]
        self.ip += 1
        return byte

    def interpret(self, chunk : Chunk):
        self.chunk = chunk
        while self.ip < len(chunk.code):
            opcode = Opcode(self.read_byte(chunk))
            match opcode:
                case Opcode.CONST:
                    idx   = self.read_byte(chunk)
                    value = chunk.constants[idx]
                    self.stack.append(value)
                    return InterpretResult.OK
                case Opcode.RET:
                    print(self.stack.pop())
                    return InterpretResult.HALT
                case Opcode.LT:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a < b)
                    return InterpretResult.OK
                case Opcode.LTE:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a <= b)
                    return InterpretResult.OK
                case Opcode.GT:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a > b)
                    return InterpretResult.OK
                case Opcode.GTE:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a >= b)
                    return InterpretResult.OK
                case Opcode.EQ:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a == b)
                    return InterpretResult.OK
                case Opcode.NOT_EQ:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a != b)
                    return InterpretResult.OK
                case Opcode.ADD:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a + b)
                    return InterpretResult.OK
                case Opcode.SUB:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a - b)
                    return InterpretResult.OK
                case Opcode.MULT:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a * b)
                    return InterpretResult.OK
                case Opcode.DIV:
                    b = self.stack.pop()
                    a = self.stack.pop()
                    self.stack.append(a / b)
                    return InterpretResult.OK
                case Opcode.NEG:
                    a = self.stack.pop()
                    self.stack.append(-a)
                    return InterpretResult.OK
                case _:
                    print(f'{opcode} unhandled')
                    return InterpretResult.RUNTIME_ERR
        return InterpretResult.OK

def main():
    file_name = 'tests/compare.py'
    with open(file_name) as file:
        src = file.read()
        node = ast.parse(src, filename=file_name)
        log_lvl = LogLevel.INFO
        if log_lvl.value > 0:
            print('-' * (len(str(log_lvl)) + 4))
            print('| ' + str(log_lvl) + ' |')
            print('-' * (len(str(log_lvl)) + 4))

        if log_lvl.value > 0:
            print('')
            print('-----------------')
            print('| Nodes visited |')
            print('-----------------')
        compiler = Compiler(loglvl=log_lvl)
        compiler.visit(node)

        if log_lvl.value > 0:
            print('')
            print('----------------')
            print('| Dissassembly |')
            print('----------------', end='')
            for chunk in compiler.chunks:
                print('')
                chunk.disass()

        if log_lvl.value > 0:
            print('')
            print('------')
            print('| VM |')
            print('------')
        vm = VM()
        while True:
            res = vm.interpret(compiler.chunk)
            match res:
                case InterpretResult.OK:
                    continue
                case InterpretResult.COMPILE_ERR:
                    print('compiler error')
                    return
                case InterpretResult.RUNTIME_ERR:
                    print('runtime error')
                    return
                case InterpretResult.HALT:
                    return
                case _:
                    print(f'unknown error {res}')
                    return

if __name__ == '__main__':
    main()
