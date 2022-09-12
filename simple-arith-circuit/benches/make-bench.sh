#! /bin/sh

# Construct a long chain of inverters to test reader scalability.
file=bf-gigantic.txt
: > $file
gate_count=100000000
wire_count=$((gate_count+1))
echo $gate_count $wire_count >> $file
echo 1 1 >> $file # number-of-input-values number-of-wires-each-input-value...
echo 1 1 >> $file # number-of-output-values number-of-wires-each-output-value...
echo >> $file
i=0
while [ $i -lt $wire_count ]; do
	echo 1 1 $i $((i+1)) INV >> $file
	i=$((i+1))
done
