from __future__ import print_function
import sys

from pycparser import c_parser, c_ast

#sys.path.extend(['.', '..'])

# A simple visitor for FuncDef nodes that prints the names and
# locations of function definitions.
class FuncDefVisitor(c_ast.NodeVisitor):
    def visit_FuncDef(self, node):
        print('%s at %s' % (node.decl.name, node.decl.coord))


def show_func_defs(preprocessed_file):
    parser = c_parser.CParser()
    with open(preprocessed_file) as f:
        ast = parser.parse(text=f.read())
        v = FuncDefVisitor()
        v.visit(ast)


if __name__ == "__main__":
    show_func_defs(sys.argv[1])
