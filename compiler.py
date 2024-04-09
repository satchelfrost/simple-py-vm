import ast
from enum import Enum

class LogLevel(Enum):
    NONE    = 0
    INFO    = 1
    VERBOSE = 2
    WARNING = 3
    ERROR   = 4

class Opcode(Enum):
    CONSTANT = 0
    RETURN   = 1

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
            case Opcode.CONSTANT:
                idx   = self.code[offset + 1]
                value = self.constants[idx]
                print(f'{offset:04} {opcode} {value}')
                return offset + 2
            case Opcode.RETURN:
                print(f'{offset:04} | {opcode}')
                return offset + 1
            case _:
                print(f'unknown opcode {opcode}')
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
                    print(node)

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
        assert len(self.chunk.constants) < 256, "exceeded constants for chunk"
        self.chunk.constants.append(node.value)
        self.chunk.code.append(Opcode.CONSTANT.value)
        self.chunk.code.append(len(self.chunk.constants) - 1)

    def visit_Compare(self, node: ast.Compare):
        self.log_node(node)
        assert len(node.comparators) == 1, "only a single comparison operand allowed"
        assert len(node.ops) == 1, "only a single comparison operator allowed"
        self.visit(node.left)
        self.visit(node.comparators[0])
        self.visit(node.ops[0])

    def visit_Assign(self, node : ast.Assign):
        self.log_node(node)

    def visit_Name(self, node : ast.Name):
        self.log_node(node)

    def visit_FunctionDef(self, node : ast.FunctionDef):
        self.log_node(node)

    def visit_Return(self, node : ast.Return):
        self.visit(node.value)
        self.chunk.code.append(Opcode.RETURN.value)

    def visit_BinOp(self, node : ast.BinOp):
        self.log_node(node)

    def visit_Add(self, node : ast.Add):
        self.log_node(node)

    def visit_Sub(self, node : ast.Sub):
        self.log_node(node)

    def visit_And(self, node : ast.And):
        self.log_node(node)

    def visit_BitAnd(self, node : ast.BitAnd):
        self.log_node(node)

    def visit_Or(self, node : ast.Or):
        self.log_node(node)

    def visit_BitOr(self, node : ast.BitOr):
        self.log_node(node)

    def visit_BitXor(self, node : ast.BitXor):
        self.log_node(node)

    def visit_Mult(self, node : ast.Mult):
        self.log_node(node)

    def visit_Div(self, node : ast.Div):
        self.log_node(node)

    def visit_Lt(self, node : ast.Lt):
        self.log_node(node)

    def visit_LtE(self, node : ast.LtE):
        self.log_node(node)

    def visit_Gt(self, node : ast.Gt):
        self.log_node(node)

    def visit_GtE(self, node : ast.GtE):
        self.log_node(node)

    def visit_Eq(self, node : ast.Eq):
        self.log_node(node)

    def visit_NotEq(self, node : ast.NotEq):
        self.log_node(node)

    def visit_While(self, node : ast.For):
        self.log_node(node)

    def visit_If(self, node : ast.If):
        self.log_node(node)

    def visit_Call(self, node : ast.Call):
        self.log_node(node)

class VM:
    def __init__(self):
        self.ip = 0

    def read_byte(self, chunk):
        byte = chunk.code[self.ip]
        self.ip += 1
        return byte

    def interpret(self, chunk : Chunk):
        while True:
            try:
                addr   = self.ip
                opcode = Opcode(self.read_byte(chunk))
                match opcode:
                    case Opcode.CONSTANT:
                        idx   = self.read_byte(chunk)
                        value = chunk.constants[idx]
                        print(f'{addr} {opcode} {value}')
                    case Opcode.RETURN:
                        print(f'{addr} | {opcode}')
            except IndexError:
                print("program finished")
                return

def main():
    file_name = "tests/compare.py"
    with open(file_name) as file:
        src = file.read()
        node = ast.parse(src, filename=file_name)
        log_lvl = LogLevel.INFO
        if log_lvl.value > 0:
            print('-' * (len(str(log_lvl)) + 4))
            print('| ' + str(log_lvl) + ' |')
            print('-' * (len(str(log_lvl)) + 4))

        compiler = Compiler(loglvl=log_lvl)
        if log_lvl.value > 0:
            print("")
            print('-----------------')
            print('| Nodes visited |')
            print('-----------------')
        compiler.visit(node)

        if log_lvl.value > 0:
            print("")
            print("----------------")
            print("| Dissassembly |")
            print("----------------")
            for chunk in compiler.chunks:
                chunk.disass()
                print("")

        # print("\nVM")
        # vm = VM()
        # vm.interpret(compiler.chunk)

if __name__ == '__main__':
    main()
