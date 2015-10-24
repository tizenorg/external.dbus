#!/bin/bash
#################################################################################
#
#   File name: test-broadcasts.sh
#
#  Created on: 2014.02.10
#     Authors: l.stempien
#              m.eljasiewic
#
#################################################################################

RECEIVE_PARAMETERS=('signal NULL NULL /samsung/test/broadcast TestMember argX NULL NULL')
SHOULD_PASS_SEND=(
                    'signal NULL samsung.test.broadcast /samsung/test/broadcast TestMember argX NULL NULL',
                    'signal NULL samsung.test.XYZ /samsung/test/broadcast TestMember argX NULL NULL', # different interface
                    'signal NULL samsung.test.broadcast /samsung/test/broadcast TestMember argX argY NULL' # different arg1
)

# seems that interface and path are required always
SHOULD_NOT_PASS_SEND=(
                    'signal NULL samsung.test.XYZ /samsung/test/broadcast TestMember NULL NULL NULL', # invalid arg0
                    'signal NULL samsung.test.XYZ /samsung/test/other TestMember argX NULL NULL', # invalid path
                    'signal NULL samsung.test.other /samsung/test/broadcast OtherMember argX NULL NULL' # invalid member

)


# SHOULD PASS THESE CASES
I=1

for param in "${SHOULD_PASS_SEND[@]}"; do
    echo "Broadcast test #$I:"
    ./serverClient-broadcast recv ${RECEIVE_PARAMETERS[0]} &
    SERVER1=`echo $!`

    sleep 1

    ./serverClient-broadcast send $param
    SERVER2=`echo $!`

    wait $SERVER1  > /dev/null 2>&1
    my_status=$?
    if [ $my_status -eq 0 ]; then
            echo "PASS"

    else
            echo "FAIL"
    fi
    I=$((I + 1))
done


# SHOULD NOT PASS THESE CASES
I=1

for param in "${SHOULD_NOT_PASS_SEND[@]}"; do
    echo "Broadcast test should NOT pass #$I:"
    ./serverClient-broadcast recv ${RECEIVE_PARAMETERS[0]} &
    SERVER1=`echo $!`

    sleep 1

    ./serverClient-broadcast send $param
    SERVER2=`echo $!`

    wait $SERVER1  > /dev/null 2>&1
    my_status=$?

    if [ $my_status -eq 0 ]; then
            echo "FAIL"
            #exit 1

    elif [ $my_status -eq 255 ]; then
            echo "FAIL"

    else
            echo "PASS"

    fi
    I=$((I + 1))
done
