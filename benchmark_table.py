import json
from statistics import mean, stdev
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--latex', action='store_true')
args = parser.parse_args()

def nice(params, latex: bool):
    n, t, D = tuple(map(int, params.split("_")))
    if latex:
        return {
            "n": f"$n = {n}$",
            "t": f"$t = {t}$",
            "D": f"$\\abs{{\\votedomain}} = {D}$"
        }
    return {
        "n": f"n = {n}",
        "t": f"t = {t}",
        "D": f"|D| = {D}"
    }


with open("benchmarks.json") as f:
    benchmarks = json.load(f)

table = "" if args.latex else '\n+------------+----------------------+--------+--------+------------+\n'

for params in benchmarks:
    runtime = {}
    runtime["ve_prove"] = [benchmarks[params][i]["runtime"]["ve_prove"] for i in range(len(benchmarks[params]))]
    runtime["ve_verify"] = [benchmarks[params][i]["runtime"]["ve_verify"] for i in range(len(benchmarks[params]))]
    runtime["ve_all"] = [benchmarks[params][i]["runtime"]["ve_prove"] + benchmarks[params][i]["runtime"]["ve_verify"] for i in range(len(benchmarks[params]))]
    runtime["user_vep_prove"] = [benchmarks[params][i]["runtime"]["user_vep_prove"] for i in range(len(benchmarks[params]))]
    runtime["user_vep_verify"] = [benchmarks[params][i]["runtime"]["user_vep_verify"] for i in range(len(benchmarks[params]))]
    runtime["user_vep_all"] = [benchmarks[params][i]["runtime"]["user_vep_prove"] + benchmarks[params][i]["runtime"]["user_vep_verify"] for i in range(len(benchmarks[params]))]
    runtime["server_vep_prove"] = [benchmarks[params][i]["runtime"]["server_vep_prove"] for i in range(len(benchmarks[params]))]
    runtime["server_vep_verify"] = [benchmarks[params][i]["runtime"]["server_vep_verify"] for i in range(len(benchmarks[params]))]
    runtime["server_vep_all"] = [benchmarks[params][i]["runtime"]["server_vep_prove"] + benchmarks[params][i]["runtime"]["server_vep_verify"] for i in range(len(benchmarks[params]))]
    runtime["intersection"] = [benchmarks[params][i]["runtime"]["intersection"] for i in range(len(benchmarks[params]))]
    runtime["full_protocol"] = [benchmarks[params][i]["runtime"]["full_protocol"] for i in range(len(benchmarks[params]))]

    bandwidth = {}
    bandwidth["ve_statement"] = [benchmarks[params][i]["bandwidth"]["ve_statement"] for i in range(len(benchmarks[params]))]
    bandwidth["ve_proof"] = [benchmarks[params][i]["bandwidth"]["ve_proof"] for i in range(len(benchmarks[params]))]
    bandwidth["user_vep_input"] = [benchmarks[params][i]["bandwidth"]["user_vep_input"] for i in range(len(benchmarks[params]))]
    bandwidth["user_vep_statement"] = [benchmarks[params][i]["bandwidth"]["user_vep_statement"] for i in range(len(benchmarks[params]))]
    bandwidth["user_vep_proof"] = [benchmarks[params][i]["bandwidth"]["user_vep_proof"] for i in range(len(benchmarks[params]))]
    bandwidth["server_vep_input"] = [benchmarks[params][i]["bandwidth"]["server_vep_input"] for i in range(len(benchmarks[params]))]
    bandwidth["server_vep_statement"] = [benchmarks[params][i]["bandwidth"]["server_vep_statement"] for i in range(len(benchmarks[params]))]
    bandwidth["server_vep_proof"] = [benchmarks[params][i]["bandwidth"]["server_vep_proof"] for i in range(len(benchmarks[params]))]
    bandwidth["ballots"] = [benchmarks[params][i]["bandwidth"]["ballots"] for i in range(len(benchmarks[params]))]
    bandwidth["full_protocol"] = [benchmarks[params][i]["bandwidth"]["full_protocol"] for i in range(len(benchmarks[params]))]

    if args.latex:
        table += "\n\t\t   & total & %.1f & %.1f & %.1f \\\\"  % (                                                          mean(runtime["full_protocol"])/1000,     stdev(runtime["full_protocol"])/1000,     (bandwidth["full_protocol"][0])/1024)
        table += "\n\t\t%s & \\ve.\\Evaloninput \\& check            & %.1f & %.1f & %.1f \\\\"        % (   nice(params, args.latex)["n"] ,     mean(runtime["ve_all"])/1000,          stdev(runtime["ve_all"])/1000,          (bandwidth["ve_statement"][0] + bandwidth["ve_proof"][0])/1024)
        # table += "\n\t\t%s & \\ve.\\Evaloninput             & %.1f & %.1f & %.1f \\\\"        % (   nice(params, args.latex)["n"] ,     mean(runtime["ve_prove"])/1000,          stdev(runtime["ve_prove"])/1000,          (bandwidth["ve_statement"][0] + bandwidth["ve_proof"][0])/1024)
        # table += "\n\t\t%s & \\ve check             & %.1f & %.1f & --- \\\\"         % (           nice(params, args.latex)["t"] ,     mean(runtime["ve_verify"])/1000,         stdev(runtime["ve_verify"])/1000)
        table += "\n\t\t%s & \\vep.\\Evaloninput \\& check (\\user)      & %.1f & %.1f & %.1f \\\\"      % (  nice(params, args.latex)["t"] ,     mean(runtime["user_vep_all"])/1000,    stdev(runtime["user_vep_all"])/1000,    (bandwidth["user_vep_input"][0] + bandwidth["user_vep_statement"][0] + bandwidth["user_vep_proof"][0])/1024)
        # table += "\n\t\t%s & \\vep.\\Evaloninput (\\user)      & %.1f & %.1f & %.1f \\\\"      % (  nice(params, args.latex)["D"] ,     mean(runtime["user_vep_prove"])/1000,    stdev(runtime["user_vep_prove"])/1000,    (bandwidth["user_vep_input"][0] + bandwidth["user_vep_statement"][0] + bandwidth["user_vep_proof"][0])/1024)
        # table += "\n\t\t   & \\vep check (\\user)      & %.1f & %.1f & --- \\\\"         % (                                mean(runtime["user_vep_verify"])/1000,   stdev(runtime["user_vep_verify"])/1000)
        table += "\n\t\t%s   & \\vep.\\Evaloninput \\& check (\\srv)       & %.1f & %.1f & %.1f \\\\"        % (  nice(params, args.latex)["D"] ,                     mean(runtime["server_vep_all"])/1000,  stdev(runtime["server_vep_all"])/1000,  (bandwidth["server_vep_input"][0] + bandwidth["server_vep_statement"][0] + bandwidth["server_vep_proof"][0])/1024)
        # table += "\n\t\t   & \\vep.\\Evaloninput (\\srv)       & %.1f & %.1f & %.1f \\\\"        % (                        mean(runtime["server_vep_prove"])/1000,  stdev(runtime["server_vep_prove"])/1000,  (bandwidth["server_vep_input"][0] + bandwidth["server_vep_statement"][0] + bandwidth["server_vep_proof"][0])/1024)
        # table += "\n\t\t   & \\vep check (\\srv)       & %.1f & %.1f & --- \\\\"         % (                                mean(runtime["server_vep_verify"])/1000, stdev(runtime["server_vep_verify"])/1000)
        table += "\n\t\t   & ballot intersection   & %.1f & %.1f & %.1f \\\\\\midrule" % (                                  mean(runtime["intersection"])/1000,      stdev(runtime["intersection"])/1000,      (bandwidth["ballots"][0])/1024)
    else:
        table += ('| {:10} | {:20} | {:^15} | {:10} |\n'.format("Parameters", "Phase", "Runtime (s)", "Bandwidth"))
        table += ('| {:10} | {:20} | {:6} | {:6} | {:10} |\n'.format("", "", "mean", "st.dev", ""))
        table += ('+------------+----------------------+--------+--------+------------+\n')
        table += ('| {:10} | {:20} | {:6} | {:6} | {:10} |\n'.format(
            "",
            "total",
            "%.1f" % (mean(runtime["full_protocol"])/1000),
            "%.1f" % (stdev(runtime["full_protocol"])/1000),
            "%.1f" % ((bandwidth["full_protocol"][0])/1024)
        ))
        table += ('| {:10} | {:20} | {:6} | {:6} | {:10} |\n'.format(
            nice(params, args.latex)["n"],
            "VE.Eval & check",
            "%.1f" % (mean(runtime["ve_all"])/1000),
            "%.1f" % (stdev(runtime["ve_all"])/1000),
            "%.1f" % ((bandwidth["ve_statement"][0] + bandwidth["ve_proof"][0])/1024)
        ))
        # table += "\n\t\t%s & \\ve.\\Evaloninput             & %.1f & %.1f & %.1f \\\\"        % (   nice(params, args.latex)["n"] ,     mean(runtime["ve_prove"])/1000,          stdev(runtime["ve_prove"])/1000,          (bandwidth["ve_statement"][0] + bandwidth["ve_proof"][0])/1024)
        # table += "\n\t\t%s & \\ve check             & %.1f & %.1f & --- \\\\"         % (           nice(params, args.latex)["t"] ,     mean(runtime["ve_verify"])/1000,         stdev(runtime["ve_verify"])/1000)
        table += ('| {:10} | {:20} | {:6} | {:6} | {:10} |\n'.format(
            nice(params, args.latex)["t"],
            "VEP.Eval & check (U)",
            "%.1f" % (mean(runtime["user_vep_all"])/1000),
            "%.1f" % (stdev(runtime["user_vep_all"])/1000),
            "%.1f" % ((bandwidth["user_vep_input"][0] + bandwidth["user_vep_statement"][0] + bandwidth["user_vep_proof"][0])/1024)
        ))
        # table += "\n\t\t%s & \\vep.\\Evaloninput (\\user)      & %.1f & %.1f & %.1f \\\\"      % (  nice(params, args.latex)["D"] ,     mean(runtime["user_vep_prove"])/1000,    stdev(runtime["user_vep_prove"])/1000,    (bandwidth["user_vep_input"][0] + bandwidth["user_vep_statement"][0] + bandwidth["user_vep_proof"][0])/1024)
        # table += "\n\t\t   & \\vep check (\\user)      & %.1f & %.1f & --- \\\\"         % (                                mean(runtime["user_vep_verify"])/1000,   stdev(runtime["user_vep_verify"])/1000)
        table += ('| {:10} | {:20} | {:6} | {:6} | {:10} |\n'.format(
            nice(params, args.latex)["D"],
            "VEP.Eval & check (S)",
            "%.1f" % (mean(runtime["server_vep_all"])/1000),
            "%.1f" % (stdev(runtime["server_vep_all"])/1000),
            "%.1f" % ((bandwidth["server_vep_input"][0] + bandwidth["server_vep_statement"][0] + bandwidth["server_vep_proof"][0])/1024)
        ))
        # table += "\n\t\t   & \\vep.\\Evaloninput (\\srv)       & %.1f & %.1f & %.1f \\\\"        % (                        mean(runtime["server_vep_prove"])/1000,  stdev(runtime["server_vep_prove"])/1000,  (bandwidth["server_vep_input"][0] + bandwidth["server_vep_statement"][0] + bandwidth["server_vep_proof"][0])/1024)
        # table += "\n\t\t   & \\vep check (\\srv)       & %.1f & %.1f & --- \\\\"         % (                                mean(runtime["server_vep_verify"])/1000, stdev(runtime["server_vep_verify"])/1000)
        table += ('| {:10} | {:20} | {:6} | {:6} | {:10} |\n'.format(
            "",
            "ballot intersection",
            "%.1f" % (mean(runtime["intersection"])/1000),
            "%.1f" % (stdev(runtime["intersection"])/1000),
            "%.1f" % ((bandwidth["ballots"][0])/1024)
        ))
        table += ('+------------+----------------------+--------+--------+------------+\n')


print(table)
