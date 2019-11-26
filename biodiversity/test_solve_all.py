import angr
import claripy


for l in range(0,49):

    sym_arg_size = 32
    sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)

    p = angr.Project(str(l))
    argv = [p.filename]
    argv.append(sym_arg)

    state = p.factory.entry_state(args=argv)

    for byte in sym_arg.chop(8):
        state.add_constraints(byte >= '\x20') # ' '
        state.add_constraints(byte <= '\x7e') # '~' 


    while True:
        succ = state.step()
        if len(succ.successors) > 1:
            break
        #print (state)
        state = succ.successors[0]

    #import IPython ;IPython.embed()

    state1, state2 = succ.successors
    s = hex(state1.solver.eval(sym_arg))[2:-1]

    n = 2
    tx = [s[i:i+n] for i in range(0, len(s), n)]
    cx = [chr(int(i,16)) for i in tx]

    sl = ''
    sl = sl.join(cx)
    print (sl)


