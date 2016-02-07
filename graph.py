import sys
import matplotlib.pyplot as plt
import numpy as np
from pylab import *

def graph(ms, server, client, ssents, csents, fname):
    width = 0.8 / (2 * len(ms))

    fig = plt.figure(figsize=(8,6))
    ax = fig.add_subplot(1,1,1)
    axx = ax.twiny()
    ax.set_xlim((0.0, 3.0))

    if ssents is not None and csents is not None:
        axy = ax.twinx()
        axy.set_ylim((0, 80000))
        axy.set_ylabel('data sent (Kb)')
        axy.set_xlim((0.0, 3.0))
    else:
        axy = None

    colors = ['#{0}{1}{2}'.format(hex(114)[2:], hex(147)[2:], hex(203)[2:]),
              '#{0}{1}{2}'.format(hex(132)[2:], hex(186)[2:], hex(91)[2:])]
    dotcolors = ['#{0}{1}{2}'.format(hex(57)[2:], hex(106)[2:], hex(177)[2:]),
                 '#{0}{1}{2}'.format(hex(62)[2:], hex(150)[2:], hex(81)[2:])]

    total = []
    for i, m in enumerate(ms):
        ind = [i + 0.1, i + 0.1 + 2*width, i + 0.1 + 4*width]
        total.extend(ind)
        r1 = ax.bar(np.array(ind), server[m], width, color=colors[0])
        ind = [i + 0.1 + width, i + 0.1 + 3*width, i + 0.1 + 5*width]
        r2 = ax.bar(ind, client[m], width, color=colors[1])

        if axy is not None:
            s1 = axy.scatter(np.array(ind) - width / 2, ssents[m], color=dotcolors[0])
            s2 = axy.scatter(np.array(ind) + width / 2, csents[m], color=dotcolors[1])
            axy.legend((s1, s2), ('Server', 'Client'), loc='upper right')
    total = np.array(total)
    ax.set_xlabel('number of gates')
    ax.set_xticks(total + width)
    ax.set_xticklabels(tuple(['$10^3$', '$10^4$', '$10^5$',
                              '$10^3$', '$10^4$', '$10^5$',
                              '$10^3$', '$10^4$', '$10^5$']))
    ax.set_ylabel('time (s)')
    ax.set_yscale('log')

    axx.set_xlim(ax.get_xlim())
    axx.set_xlabel('number of attributes')
    axx.set_xticks(np.array([0.5, 1.5, 2.5]))
    axx.set_xticklabels(['$10$', '$100$', '$1000$'])

    ax.legend((r1[0], r2[0]), ('Server', 'Client'), loc='upper left')
    fig.savefig(fname)
    # show()

def main(argv):
    qs = {}
    scomps, scomms, ccomps, ccomms, ssents, csents = {}, {}, {}, {}, {}, {}
    plt.rcParams['text.usetex'] = True
    plt.rcParams['font.size'] = 14
    plt.rcParams['font.family'] = 'Computer Modern'
    plt.rcParams['axes.labelsize'] = plt.rcParams['font.size']
    plt.rcParams['axes.titlesize'] = 1.5*plt.rcParams['font.size']
    plt.rcParams['legend.fontsize'] = plt.rcParams['font.size']
    plt.rcParams['xtick.labelsize'] = plt.rcParams['font.size']
    plt.rcParams['ytick.labelsize'] = plt.rcParams['font.size']
    plt.rcParams['legend.frameon'] = False
    # plt.rcParams['legend.loc'] = 'upper right'
    plt.rcParams['axes.linewidth'] = 1

    f = open('results.txt', 'r')
    line = f.readline()
    current = 0
    while line != '':
        m, q = line.split()
        m, q = int(m), int(q)
        _, scomp, scomm, ssent, _ = f.readline().split()
        scomp, scomm, ssent = float(scomp), float(scomm), int(ssent) * 8 / 1000
        _, ccomp, ccomm, csent, _ = f.readline().split()
        ccomp, ccomm, csent = float(ccomp), float(ccomm), int(csent) * 8 / 1000
        try:
            qs[m].append(q)
        except KeyError:
            qs[m] = [q]
        try:
            scomps[m].append(scomp)
        except KeyError:
            scomps[m] = [scomp]
        try:
            scomms[m].append(scomm)
        except KeyError:
            scomms[m] = [scomm]
        try:
            ccomps[m].append(ccomp)
        except KeyError:
            ccomps[m] = [ccomp]
        try:
            ccomms[m].append(ccomm)
        except KeyError:
            ccomms[m] = [ccomm]
        try:
            ssents[m].append(ssent)
        except KeyError:
            ssents[m] = [ssent]
        try:
            csents[m].append(csent)
        except KeyError:
            csents[m] = [csent]

        line = f.readline()

    ms = list(qs.keys())
    ms.sort()
    graph(ms, scomps, ccomps, None, None, 'computation.png')
    graph(ms, scomms, ccomms, ssents, csents, 'communication.png')

if __name__ == "__main__":
    main(sys.argv)
