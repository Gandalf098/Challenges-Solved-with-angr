import angr , IPython

### it took like 8 hrs to develop the script
### takes approx. 30 mins to run

p = angr.project.Project('babyrev.exe')

#sz = 0x2

#enc = [ 0x9e , 0x53 ]

enc = [ 0x4A, 0xDD, 0x9B, 0xA9, 0x24, 0x43, 0x50, 0x13, 0x24, 0x3B, 0x50, 0x9D, 0xA7, 0x6D, 0x3C, 0x98, 0x24, 0x79, 0x3C, 0x13, 0x13, 0x3F, 0x7A, 0x27, 0x9B, 0x6D, 0x3C, 0x51, 0x24, 0x98, 0x6E, 0x3F, 0x24, 0x75, 0xD5, 0xB3 ]

sz = len(enc)

def non (s):
    pass

p.hook (0x140011a7d ,non ,length=5)
p.hook (0x140011a92 ,non ,length=5)
p.hook (0x140011aca ,non ,length=5)
p.hook (0x140011ad9 ,non ,length=5)
p.hook (0x140011b78 ,non ,length=5)
p.hook (0x1400117af ,non ,length=5)


s = p.factory.call_state (0x140011970)

sgr = p.factory.simgr(s)




while True:
    if ( len(sgr.active) > 1 ) or ( '0x140011a2a' in [ hex(i.addr) for i in sgr.active ]  ):
        break
    print (sgr.active)
    sgr.step()

sgr.move ( from_stash='active' , to_stash= 'stashed' , filter_func=lambda s : s.addr == 0x1400119b2)

print ('first condition stashed (error please enter file cond)')

while True:
    if ( len(sgr.active) > 1 ) or ( '0x140011a2a' in [ hex(i.addr) for i in sgr.active ]  ):
        break
    print (sgr.active)
    sgr.step()

#IPython.embed()



print ('setting size to ' + str(sz))

sgr.active[0].regs.eax = sz

while True:
    if ( len(sgr.active) > 1 ) or ( '0x140011a49' in [ hex(i.addr) for i in sgr.active ]  ):
        break
    print (sgr.active)
    sgr.step()

sgr.active[0].regs.rax = 0xc0000000 
malloc_1 = 0xc0000000

print ('setting malloc1 addr' )



while True:
    if ( len(sgr.active) > 1 ) or ( '0x140011a69' in [ hex(i.addr) for i in sgr.active ]  ):
        break
    print (sgr.active)
    sgr.step()

sgr.active[0].regs.rax = 0xc0000000 + sz
malloc_2 = 0xc0000000 + sz

print ('setting malloc2 addr' )

while True:
    if ( len(sgr.active) > 1 ) or ( '0x140011ac7' in [ hex(i.addr) for i in sgr.active ]  ):
        break
    print (sgr.active)
    sgr.step()

#v = sgr.active[0].memory.make_symbolic('v',malloc_1 ,2)
#IPython.embed()

while True:
    if ( len(sgr.active) > 1 ) or ( '0x140011bd5' in [ hex(i.addr) for i in sgr.active ]  ):
        break
    print (sgr.active)
    sgr.step()

#IPython.embed()

state = sgr.active[0]

i = 0

IPython.embed()

while ( i < sz ):
    v = state.memory.make_symbolic('v',malloc_2 + i,1)
    state.add_constraints ( v == enc[i] )
    i = i + 1
    print ( 'i == ' + str (i) )

s = ''
cx = []

i = 0

while ( i < sz ):
    v = state.memory.make_symbolic('v',malloc_1 + i ,1)

    state.add_constraints( v >= '\x20' )
    state.add_constraints( v <= '\x7e' )

    t = state.solver.eval (v)
    cx . append ( chr(t) )

    i = i + 1

    print (cx)


print (' flag is `cuz KHALED Loves FLAGS\' ' + s.join(cx) )



