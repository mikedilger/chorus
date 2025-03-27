#!/bin/bash

if [ ! -x relay-tester ] ; then
    echo "You must build https://github.com/mikedilge/relay-tester and copy the "
    echo "resultant target/release/relay-tester binary into this directory."
    exit 1
fi

./relay-tester \
    ws://localhost:8080/ \
    nsec16xfd467kyd3xpu9x5u4933u00v73xrl0jyq9rk5ktd9t2j38k20qtwxuj3 \
    nsec1l50yuf6uxm2l5qxm87fkm56z3m7g88jnfy5s6az5wscxpu5l2yqq6qwk88
