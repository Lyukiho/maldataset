"""IDA 9 / IDAPython batch extractor for one PE sample.

Run inside IDA, for example:

    idat.exe -A -c -oOUTPUT.i64 -LIDA.log \
      -S"ida_extract_sample.py OUTPUT.json 48" SAMPLE.exe

The script never executes the input program.  It exports program structure for
all discovered functions and Hex-Rays pseudocode for a ranked subset.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import sys
import time
import traceback
from collections import Counter, defaultdict, deque

import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_ida
import ida_idp
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_pro
import ida_segment
import ida_ua
import idautils
import idc


SCHEMA_VERSION = 1
DEFAULT_MAX_DECOMPILED_FUNCTIONS = 48
MAX_PSEUDOCODE_CHARS_PER_FUNCTION = 100_000
MAX_EXPORTED_STRINGS = 5_000
MAX_STRING_CHARS = 512

SENSITIVE_API_TERMS = {
    "process_injection": (
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntmapviewofsection", "queueuserapc", "setthreadcontext", "openprocess",
    ),
    "memory_protection": (
        "virtualprotect", "virtualalloc", "ntprotectvirtualmemory",
        "rtlmovememory", "flushinstructioncache",
    ),
    "persistence": (
        "regsetvalue", "createservice", "startservice", "setwindowshook",
        "createscheduledtask", "shellexecute",
    ),
    "network": (
        "internetopen", "internetconnect", "httpopenrequest", "winhttp",
        "wsastartup", "connect", "send", "recv", "urldownloadtofile", "dnsquery",
    ),
    "dynamic_resolution": ("loadlibrary", "getprocaddress", "ldrloaddll"),
    "anti_analysis": (
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "queryperformancecounter", "gettickcount", "outputdebugstring",
    ),
    "credential_crypto": (
        "cryptunprotectdata", "cryptdecrypt", "bcryptdecrypt", "credread",
        "lsaretrieveprivatedata",
    ),
}


def hex_ea(ea):
    return f"0x{int(ea):x}"


def clean_name(name):
    return ida_lines.tag_remove(name or "")


def sensitive_categories(api_names):
    names = " ".join(api_names).lower()
    return sorted(
        category
        for category, terms in SENSITIVE_API_TERMS.items()
        if any(term in names for term in terms)
    )


def enumerate_imports():
    modules = []
    by_ea = {}
    module_count = ida_nalt.get_import_module_qty()
    for index in range(module_count):
        module_name = ida_nalt.get_import_module_name(index) or f"module_{index}"
        entries = []

        def callback(ea, name, ordinal):
            import_name = clean_name(name) if name else f"ordinal_{ordinal}"
            record = {
                "ea": hex_ea(ea),
                "name": import_name,
                "ordinal": int(ordinal),
                "module": module_name,
            }
            entries.append(record)
            by_ea[int(ea)] = record
            return True

        ida_nalt.enum_import_names(index, callback)
        modules.append({"name": module_name, "imports": entries})
    return modules, by_ea


def enumerate_strings():
    all_strings = []
    refs_by_function = defaultdict(list)
    total_strings = 0
    strings = idautils.Strings()
    strings.setup(ignore_instructions=True)
    for item in strings:
        total_strings += 1
        value = str(item)
        record = {
            "ea": hex_ea(item.ea),
            "length": int(item.length),
            "type": int(item.strtype),
            "value": value[:MAX_STRING_CHARS],
            "truncated": len(value) > MAX_STRING_CHARS,
        }
        ref_functions = set()
        for xref in idautils.XrefsTo(item.ea, 0):
            function = ida_funcs.get_func(xref.frm)
            if function:
                ref_functions.add(int(function.start_ea))
        record["referenced_by"] = [hex_ea(ea) for ea in sorted(ref_functions)]
        for function_ea in ref_functions:
            refs_by_function[function_ea].append(record)
        if len(all_strings) < MAX_EXPORTED_STRINGS:
            all_strings.append(record)
    return all_strings, refs_by_function, total_strings


def basic_block_metrics(function):
    blocks = list(ida_gdl.FlowChart(function))
    edges = sum(sum(1 for _ in block.succs()) for block in blocks)
    return len(blocks), edges


def function_structure(function, imports_by_ea):
    start = int(function.start_ea)
    flags = int(function.flags)
    callees = set()
    api_refs = {}
    instruction_count = 0
    mnemonic_counts = Counter()

    for ea in idautils.FuncItems(start):
        item_flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_code(item_flags):
            continue
        instruction_count += 1
        mnemonic = ida_ua.print_insn_mnem(ea).lower()
        if mnemonic:
            mnemonic_counts[mnemonic] += 1

        if not ida_idp.is_call_insn(ea):
            continue
        for target in idautils.CodeRefsFrom(ea, 0):
            target = int(target)
            imported = imports_by_ea.get(target)
            if imported:
                api_refs[imported["name"]] = imported
                continue
            callee = ida_funcs.get_func(target)
            if callee and int(callee.start_ea) != start:
                callee_start = int(callee.start_ea)
                callees.add(callee_start)
                callee_name = clean_name(ida_funcs.get_func_name(callee_start))
                lowered = callee_name.lower().removeprefix("__imp_").removeprefix("_")
                if any(term in lowered for terms in SENSITIVE_API_TERMS.values() for term in terms):
                    api_refs[callee_name] = {
                        "ea": hex_ea(callee_start), "name": callee_name,
                        "ordinal": -1, "module": "thunk_or_named_target",
                    }

    block_count, cfg_edges = basic_block_metrics(function)
    return {
        "start_ea": hex_ea(start),
        "end_ea": hex_ea(function.end_ea),
        "name": clean_name(ida_funcs.get_func_name(start)),
        "size_bytes": int(function.end_ea - function.start_ea),
        "instruction_count": instruction_count,
        "basic_blocks": block_count,
        "cfg_edges": cfg_edges,
        "is_library": bool(flags & ida_funcs.FUNC_LIB),
        "is_thunk": bool(flags & ida_funcs.FUNC_THUNK),
        "callees": sorted(callees),
        "api_refs": sorted(api_refs.values(), key=lambda row: (row["module"], row["name"])),
        "sensitive_categories": sensitive_categories(api_refs),
        "top_mnemonics": mnemonic_counts.most_common(16),
    }


def entry_distance(functions, entry_ea):
    starts = {row["start_int"] for row in functions}
    entry_func = ida_funcs.get_func(entry_ea)
    if not entry_func:
        return {}
    root = int(entry_func.start_ea)
    distances = {root: 0}
    queue = deque([root])
    graph = {row["start_int"]: row["callees"] for row in functions}
    while queue:
        current = queue.popleft()
        if distances[current] >= 4:
            continue
        for target in graph.get(current, ()):
            if target in starts and target not in distances:
                distances[target] = distances[current] + 1
                queue.append(target)
    return distances


def select_functions(functions, entry_ea, maximum, seed_text):
    indegree = Counter()
    for row in functions:
        indegree.update(row["callees"])
    distances = entry_distance(functions, entry_ea)

    candidates = []
    for row in functions:
        if row["is_library"] or row["is_thunk"]:
            continue
        distance = distances.get(row["start_int"])
        score = 0.0
        reasons = []
        if distance is not None:
            score += 16.0 / (distance + 1)
            reasons.append(f"entry_distance_{distance}")
        if row["sensitive_categories"]:
            score += 12.0 + 2.0 * len(row["sensitive_categories"])
            reasons.append("sensitive_api")
        if row["api_refs"]:
            score += min(len(row["api_refs"]), 12) * 0.75
            reasons.append("imports")
        if row["string_refs"]:
            score += min(len(row["string_refs"]), 10) * 0.4
            reasons.append("strings")
        score += min(math.log2(row["instruction_count"] + 1), 10)
        score += min(indegree[row["start_int"]], 10) * 0.5
        row["selection_score"] = round(score, 4)
        row["selection_reasons"] = reasons
        row["callers"] = indegree[row["start_int"]]
        candidates.append(row)

    selected = []
    seen = set()

    def add(rows, count):
        for row in rows:
            if len(selected) >= maximum or count <= 0:
                break
            if row["start_int"] in seen:
                continue
            selected.append(row)
            seen.add(row["start_int"])
            count -= 1

    ranked = sorted(
        candidates,
        key=lambda row: (-row["selection_score"], -row["instruction_count"], row["start_int"]),
    )
    add(ranked, max(0, maximum - 12))
    add(sorted(candidates, key=lambda row: (-row["instruction_count"], row["start_int"])), 6)
    rng = random.Random(int(hashlib.sha256(seed_text.encode()).hexdigest()[:16], 16))
    shuffled = list(candidates)
    rng.shuffle(shuffled)
    add(shuffled, maximum)
    return selected[:maximum]


def decompile_selected(selected, decompiler_available):
    succeeded = 0
    for row in selected:
        row["selected_for_decompilation"] = True
        if not decompiler_available:
            row["decompilation_status"] = "hexrays_unavailable"
            continue
        try:
            cfunc = ida_hexrays.decompile(row["start_int"])
            if not cfunc:
                row["decompilation_status"] = "no_cfunc"
                continue
            lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
            pseudocode = "\n".join(lines)
            row["pseudocode"] = pseudocode[:MAX_PSEUDOCODE_CHARS_PER_FUNCTION]
            row["pseudocode_truncated"] = len(pseudocode) > MAX_PSEUDOCODE_CHARS_PER_FUNCTION
            row["decompilation_status"] = "ok"
            succeeded += 1
        except Exception as exc:
            row["decompilation_status"] = "error"
            row["decompilation_error"] = f"{type(exc).__name__}: {exc}"
    return succeeded


def segment_records():
    records = []
    for ea in idautils.Segments():
        segment = ida_segment.getseg(ea)
        if not segment:
            continue
        records.append(
            {
                "name": clean_name(ida_segment.get_segm_name(segment)),
                "start_ea": hex_ea(segment.start_ea),
                "end_ea": hex_ea(segment.end_ea),
                "size_bytes": int(segment.end_ea - segment.start_ea),
                "permissions": int(segment.perm),
                "type": int(segment.type),
            }
        )
    return records


def main():
    if len(idc.ARGV) < 2:
        raise ValueError("usage: ida_extract_sample.py OUTPUT.json [MAX_FUNCTIONS]")
    output_path = os.path.abspath(idc.ARGV[1])
    max_functions = (
        int(idc.ARGV[2]) if len(idc.ARGV) >= 3 else DEFAULT_MAX_DECOMPILED_FUNCTIONS
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    started = time.time()
    ida_auto.auto_wait()

    input_path = ida_nalt.get_input_file_path()
    entry_ea = int(ida_ida.inf_get_start_ea())
    import_modules, imports_by_ea = enumerate_imports()
    strings, string_refs, total_strings = enumerate_strings()

    functions = []
    for index in range(ida_funcs.get_func_qty()):
        function = ida_funcs.getn_func(index)
        if not function:
            continue
        row = function_structure(function, imports_by_ea)
        row["start_int"] = int(function.start_ea)
        row["string_refs"] = [
            {"ea": value["ea"], "value": value["value"]}
            for value in string_refs.get(int(function.start_ea), ())[:64]
        ]
        row["selected_for_decompilation"] = False
        functions.append(row)

    selected = select_functions(functions, entry_ea, max_functions, input_path)
    decompiler_available = bool(ida_hexrays.init_hexrays_plugin())
    decompiled = decompile_selected(selected, decompiler_available)

    for row in functions:
        row["callees"] = [hex_ea(ea) for ea in row["callees"]]
        row.pop("start_int", None)

    result = {
        "schema_version": SCHEMA_VERSION,
        "sample": {
            "input_path": input_path,
            "input_name": os.path.basename(input_path),
            "processor": ida_ida.inf_get_procname(),
            "is_64bit": bool(ida_ida.inf_is_64bit()),
            "entry_ea": hex_ea(entry_ea),
        },
        "analysis": {
            "ida_version": ida_kernwin.get_kernel_version(),
            "elapsed_seconds": round(time.time() - started, 3),
            "decompiler_available": decompiler_available,
            "function_count": len(functions),
            "selected_function_count": len(selected),
            "decompiled_function_count": decompiled,
            "decompilation_coverage_selected": (
                round(decompiled / len(selected), 6) if selected else 0.0
            ),
            "import_module_count": len(import_modules),
            "import_count": sum(len(module["imports"]) for module in import_modules),
            "string_count": total_strings,
            "exported_string_count": len(strings),
        },
        "segments": segment_records(),
        "imports": import_modules,
        "strings": strings,
        "functions": functions,
    }

    part = output_path + ".part"
    with open(part, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    os.replace(part, output_path)
    print(f"EXTRACT_OK {output_path}")


def write_failure(output_path, exc):
    if not output_path:
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "error": f"{type(exc).__name__}: {exc}",
        "traceback": traceback.format_exc(),
    }
    with open(output_path + ".error.json", "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    destination = os.path.abspath(idc.ARGV[1]) if len(idc.ARGV) >= 2 else ""
    exit_code = 0
    try:
        main()
    except BaseException as error:
        exit_code = 1
        write_failure(destination, error)
        traceback.print_exc()
    finally:
        ida_pro.qexit(exit_code)
