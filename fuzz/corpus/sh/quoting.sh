x=$(echo $(printf '%s' "a'b"))
y=`cmd arg \"nested\``
echo 'single' "double $x" \$HOME ~user/file*.[ch]
echo ${v:-def} ${v:=set} ${v:?err} ${v:+alt} ${#v} ${v%pat} ${v#pre}
