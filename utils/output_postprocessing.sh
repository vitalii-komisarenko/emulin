# Run this script over `gdb` output and over `emulin` output
# to compare them using `diff`

egrep '^r|^eflags|^cs|^ss|^ds|^es|^fs|^gs|^0x|^xmm' \
| sed -E 's/(^xmm..\s*).*v16_int8.=..(.*)., v8_int16.*/\1\2/' \
| sed -e 's/ *<.*//' \
| sed -e 's/ in.*//'
