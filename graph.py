import sys
import matplotlib.pyplot as plt
import numpy as np
from pylab import *

def graph(ms, server, client, ssents, csents, fname):
    width = 0.8 / (2 * len(ms))

    # fig = plt.figure(figsize=(6,4.3))
    fig = plt.figure()
    ax = fig.add_subplot(1,1,1)
    axx = ax.twiny()
    ax.set_xlim((0.0, 3.0))

    if ssents is not None and csents is not None:
        axy = ax.twinx()
        axy.set_ylim((0, 90))
        axy.set_ylabel('data sent (Mbit)')
        axy.set_xlim((0.0, 3.0))
    else:
        axy = None

    colors = ['#{0}{1}{2}'.format(hex(114)[2:], hex(147)[2:], hex(203)[2:]),
              '#{0}{1}{2}'.format(hex(211)[2:], hex(94)[2:], hex(96)[2:])]
    dotcolors = ['#{0}{1}{2}'.format(hex(57)[2:], hex(106)[2:], hex(177)[2:]),
                 '#{0}{1}{2}'.format(hex(204)[2:], hex(37)[2:], hex(41)[2:])]

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
            axy.legend((s1, s2), ('Server data sent', 'Client data sent'), loc='upper right')
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

    ax.legend((r1[0], r2[0]), ('Server time', 'Client time'), loc='upper left')
    fig.set_size_inches(6, 2.5)
    fig.savefig(fname, bbox_inches="tight", dpi=100)
    # show()

def main(argv):
    qs = {}
    scomps, scomms, ccomps, ccomms, ssents, csents = {}, {}, {}, {}, {}, {}
    # fig_width_pt = 600.0
    # inches_per_pt = 1.0 / 72.27
    # golden_mean = 2.0 / (sqrt(5) + 1.0)
    # fig_width = fig_width_pt * inches_per_pt
    # fig_height = fig_width * golden_mean
    # fig_size = [fig_width, fig_height]
    params = {'backend': 'ps',
              'axes.labelsize': 8,
              'font.size': 8,
              'legend.fontsize': 8,
              'xtick.labelsize': 8,
              'ytick.labelsize': 8,
              'text.usetex': True,
              # 'figure.figsize': fig_size
    }
    plt.rcParams.update(params)
    plt.rcParams['text.usetex'] = True
    # plt.rcParams['legend.frameon'] = False
    plt.rcParams['axes.linewidth'] = 1

    if len(argv) != 2:
        print('Usage: %s filename', argv[0])
        exit(1)
    f = open(argv[1], 'r')
    line = f.readline()
    current = 0
    while line != '':
        m, q = line.split()
        m, q = int(m), int(q)
        _, scomp, scomm, ssent = f.readline().split()
        scomp, scomm, ssent = float(scomp), float(scomm), int(ssent) * 8 / 1000 / 1000
        _, ccomp, ccomm, csent = f.readline().split()
        ccomp, ccomm, csent = float(ccomp), float(ccomm), int(csent) * 8 / 1000 / 1000
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
