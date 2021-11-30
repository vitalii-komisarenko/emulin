# Run this script over `gdb` output and over `emulin` output
# to compare them using `diff`

egrep '^r|^eflags|^cs|^ss|^ds|^es|^fs|^gs|^0x|^pos' \
| sed -e 's/ *<.*//' \
| sed -e 's/ in.*//' \
| sed -e 's/pos = 0x//' \
| sed -e 's/^0x0*//'
