#!/usr/bin/env python

import numpy as np

NUM = 10

with open('logs/server.200.100000.log') as f:
    garblelist = []
    verifylist = []
    encryptlist = []
    complist = []

    garble = 0.0
    verify = 0.0
    encrypt = 0.0
    comp = 0.0

    count = 0
    i = 0
    for line in f:
        if line.startswith('Garble'):
            _, time = line.split(': ')
            garblelist.append(float(time))
        if line.startswith('Verify'):
            _, time = line.split(': ')
            verifylist.append(float(time))
        if line.startswith('Encrypt'):
            _, time = line.split(': ')
            encryptlist.append(float(time))
        if line.startswith('Computation:'):
            _, time = line.split(': ')
            complist.append(float(time))
        if line.startswith('KEY'):
            i += 1
            if i % NUM == 0:
                count += 1
                garble += np.median(garblelist)
                verify += np.median(verifylist)
                encrypt += np.median(encryptlist)
                comp += np.median(complist)
    garble = np.round(garble / count, decimals=3)
    verify = np.round(verify / count, decimals=3)
    encrypt = np.round(encrypt / count, decimals=3)
    comp = np.round(comp / count, decimals=3)
    print('Garble: %.03f' % garble)
    print('Verify: %.03f' % verify)
    print('Verify (batch): %.03f' % (verify / 5.4))
    print('Encrypt: %.03f' % encrypt)
    print('Total: %.03f' % (garble + verify + encrypt))
    print('Total (opt): %.03f' % (verify / 5.4 + encrypt))
    print('Computation: %.03f' % comp)


print()
with open('logs/client.200.100000.log') as f:
    randlist = []
    declist = []
    evallist = []
    reenclist = []
    verifylist = []
    complist = []

    rand = 0.0
    dec = 0.0
    eval = 0.0
    reenc = 0.0
    verify = 0.0
    comp = 0.0

    count = 0
    i = 0
    for line in f:
        if line.startswith('Randomize'):
            _, time = line.split(': ')
            randlist.append(float(time))
        if line.startswith('Decrypt'):
            _, time = line.split(': ')
            declist.append(float(time))
        if line.startswith('Evaluate'):
            _, time = line.split(': ')
            evallist.append(float(time))
        if line.startswith('Check (re-encrypt)'):
            _, time = line.split(': ')
            reenclist.append(float(time))
        if line.startswith('Check (re-garble)'):
            _, time = line.split(': ')
            verifylist.append(float(time))
        if line.startswith('Computation:'):
            _, time = line.split(': ')
            complist.append(float(time))
        if line.startswith('KEY'):
            i += 1
            if i % NUM == 0:
                count += 1
                rand += np.median(randlist)
                dec += np.median(declist)
                eval += np.median(evallist)
                reenc += np.median(reenclist)
                verify += np.median(verifylist)
                comp += np.median(complist)
    rand = np.round(rand / count, decimals=3)
    dec = np.round(dec / count, decimals=3)
    eval = np.round(eval / count, decimals=3)
    reenc = np.round(reenc / count, decimals=3)
    verify = np.round(verify / count, decimals=3)
    comp = np.round(comp / count, decimals=3)
    print('Rand: %.03f' % rand)
    print('Decrypt: %.03f' % dec)
    print('Eval: %.03f' % eval)
    print('Reenc: %.03f' % reenc)
    print('Verify: %.03f' % verify)
    print('Total: %.03f' % (rand + dec+ eval + reenc + verify))
    print('Total (opt): %.03f' % (dec+ eval + reenc + verify))

    print('Computation: %.03f' % (comp))
