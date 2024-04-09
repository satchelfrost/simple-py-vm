import ast

class Compiler:
    def visit(self, node):
        name = node.__class__.__name__
        visitor = getattr(self, 'visit_' + name, None)
        if visitor:
            visitor(node)
        else:
            raise RuntimeError(f'visit_{name} has no implementation. {ast.dump(node)}')

    def visit_Module(self, node: ast.Module):
        for stmt in node.body:
            self.visit(stmt)

    def visit_Expr(self, node: ast.Expr):
        self.visit(node.value)

    def visit_Constant(self, node: ast.Constant):
        print("constant visited")

    def visit_Compare(self, node: ast.Compare):
        self.visit(node.left)
        assert len(node.comparators) == 1, "only a single comparison operand allowed"
        self.visit(node.comparators[0])
        assert len(node.ops) == 1, "only a single comparison operator allowed"
        self.visit(node.ops[0])

def main():
    file_name = "tests/compare.py"
    with open(file_name) as file:
        src = file.read()
        node = ast.parse(src, filename=file_name)
        compiler = Compiler()
        compiler.visit(node)

if __name__ == '__main__':
    main()
