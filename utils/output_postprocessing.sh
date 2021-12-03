# Run this script over `gdb` output and over `emulin` output
# to compare them using `diff`

egrep '^r|^eflags|^cs|^ss|^ds|^es|^fs|^gs|^0x' \
| sed -e 's/ *<.*//' \
| sed -e 's/ in.*//'
