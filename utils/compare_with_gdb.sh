LINES=300000
meld <(cat ~/tmp_gdb_output | utils/output_postprocessing.sh | head -n $LINES) <(ruby main.rb | head -n $LINES | utils/output_postprocessing.sh)
