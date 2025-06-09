# remove forced confirmations
set confirm off

# wait for program to finish
break exit
continue

# dump a region of SRAM, adjust addresses to match your target
dump binary memory dump1.bin 0x0100 0x21FF

kill
quit
