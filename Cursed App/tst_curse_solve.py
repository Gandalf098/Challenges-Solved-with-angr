import angr
import claripy


def non(s):
	pass




#sym_arg_size = 32
#sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)

p = angr.Project("./cursed_app.elf")
argv = [p.filename]
argv.append("test")

p.hook (0x401172 ,non ,length=5)
p.hook (0x40117a ,non ,length=5)


state = p.factory.call_state(0x401154)

state.regs.r12 = 0x3b

state.regs.rbp = 0xf0000000


#simfile = angr.SimFile('test',size=0x3b)

#if not ( state.fs.insert('./test', simfile) ):
#    print ('error couldn\'t insert simfile ')

while True:
    succ = state.step()
    if (state.addr == 0x40115c):
        break
    print (state)
    state = succ.successors[0]

print (state.regs.rax)
malloc = state.regs.rax

while True:
    succ = state.step()
    if (state.addr == 0x40117f):
        break
    print (state)
    state = succ.successors[0]

#v = state.memory.make_symbolic('v',0xc0000ff0,1)

# for byte in v.chop(8):
#    state.add_constraints(byte >= '\x20') # ' '
#    state.add_constraints(byte <= '\x7e') # '~'

i = 0

cx = []

while True:
    succ = state.step()
    print (state)
    if (state.addr == 0x401f3b):
        break
    if (succ.successors[0].addr != 0x401f4f):
        state = succ.successors[0]
    else:
        state = succ.successors[1]
    v = state.memory.make_symbolic('v',malloc + i,1)
    state.add_constraints ( v >= '\x20' )
    state.add_constraints ( v <= '\x7e' )
    t = state.solver.eval(v)
    print ( "piece : " + chr (t) )
    cx . append ( chr(t) )
    print (cx)
    i = i + 1
    #IPython.embed()

#state1, state2 = succ.successors

#s = hex(state1.solver.eval(sym_arg))[2:-1]

#n = 2
#tx = [s[i:i+n] for i in range(0, len(s), n)]
#cx = [chr(int(i,16)) for i in tx]

#cx = [chr(i) for i in cx]

sl = ''
sl = sl.join(cx)
print (sl)


