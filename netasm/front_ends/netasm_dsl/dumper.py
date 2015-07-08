__author__ = 'shahbaz'

from optparse import OptionParser
from parser import Parser


def main():
    op = OptionParser()
    op.add_option('--ifile', action="store", dest="ifile")
    op.add_option('--ofile', action="store", dest="ofile")

    op.set_defaults(ofile='./dump')
    options, args = op.parse_args()

    if not options.ifile:
        print '--ifile flag not specified.'
        exit(1)

    ifile = open(options.ifile)
    ofile = open(options.ofile, 'w')

    parser = Parser()
    policy, errors_cnt = parser.parse(ifile.read())

    ofile.write(str(policy))
    ofile.write('\n')
    ofile.write('Total errors: ' + str(errors_cnt))


main()
