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

MATCH_PARAMS=(  "type='signal',interface='samsung.test.broadcast',member='Foo',path='/samsung/test/broadcast',arg0='Y'", # rule 1 - for AddMatch
                "type='signal',interface='samsung.test.broadcast',member='Foo',path='/samsung/test/broadcast',arg0='X'") # rule 2 - for AddMatch and RemoveMatch

TEST_SIGNAL=("type='signal',interface='samsung.test.broadcast',member='Foo',path='/samsung/test/broadcast',arg0='X'") # test signal matches only rule 2

echo "AddMatch + RemoveMatch test:"
./serverClient-broadcast-remove-match recv ${MATCH_PARAMS[0]} ${MATCH_PARAMS[1]} &
SERVER1=`echo $!`

sleep 1

./serverClient-broadcast-remove-match send $TEST_SIGNAL  # should pass
SERVER2=`echo $!`

sleep 1
# server does RemoveMatch

./serverClient-broadcast-remove-match send $TEST_SIGNAL # should fail
SERVER2=`echo $!`

wait $SERVER1  > /dev/null 2>&1
my_status=$?
if [ $my_status -eq 0 ]; then
        echo "PASS"

else
        echo "FAIL"
        exit 1
fi
