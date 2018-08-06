#!/bin/bash
# Basic while loop
for query in {50..252}
do
    for label in {30..63}
    do
        echo "######### Label Len: "$label " Query Len:" $query "###########"
        # run stuff
        python det.py -c ./config.json -f config.json -p dns -i $label -j $query
        echo "####################  Transfer done ##########################"
        echo " "
        sleep 10
        echo " "
    done
done
echo All done