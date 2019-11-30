from subprocess import *
import string
import sys

command = "perf stat -x : -e instructions:u ./cursed_app.elf ./license 1>/dev/null"

#flag = 'ASIS{y0u_c4N_s33_7h15_15_34513R_7h4n_Y0u_7h1nk'
flag = ''

def write_file(cont):
    with open("./license", "wb") as f:
        f.write( bytes (cont , 'utf-8') )

write_file(flag)
'''
Desktop cat license
ASIS{
Desktop perf stat -x : -e instructions:u ./cursed_app.elf ./license 1>/dev/null
167689::instructions:u:377798:100.00::
'''
#ins_count = 167689
#ins_count = 169126
ins_count = 168844
#ins_count = 169784
while True:
	delta = 0
	count_chr = ''
	t = []
	for i in string.printable:
		write_file(flag + i)
		target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
		target_output = target.communicate()
                #  import pdb;pdb.set_trace()
                #  print(target_output)
		print (str ( str(target_output[0]).split(':')[0] )[2:] )
		instructions = int(str( str (target_output[0]).split(':')[0] )[2:])
		d = instructions - ins_count
#		t.append( (i,d) )
		print ( 'Trying ' + i)
		print ( str (d) )
		if ins_count + 26 > instructions > ins_count + 10:
			count_chr = i
			delta = instructions - ins_count
			ins_count = instructions
			print ('found piece :' + i)
			break
#		print ('Trying ' + i)
	flag = flag + count_chr
	print(delta, flag)
