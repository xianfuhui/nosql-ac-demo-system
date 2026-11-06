#!/usr/bin/env python3
"""Chạy notebook .ipynb (không cần Jupyter) và ghi:
   - result.json   : nội dung + output (chữ, bảng, ảnh PNG) để web hiển thị
   - executed.ipynb: notebook đã chạy, có output, mở được bằng Jupyter/Colab
Dùng: python3 run_notebook.py --notebook X.ipynb --out DIR [--csv data.csv] [--label "..."]
"""
import argparse, ast, base64, contextlib, io, json, os, sys, time, traceback, warnings

MAX_ROWS, MAX_COLS, MAX_TEXT = 40, 40, 20000

def to_table(val):
    import pandas as pd
    df = val.to_frame() if isinstance(val, pd.Series) else val
    total = len(df)
    head = df.head(MAX_ROWS).iloc[:, :MAX_COLS]
    named_index = not isinstance(df.index, pd.RangeIndex) or df.index.name
    cols = ([str(df.index.name or "")] if named_index else []) + [str(c) for c in head.columns]
    rows = []
    for idx, r in head.iterrows():
        cells = [str(x) for x in r.tolist()]
        rows.append(([str(idx)] if named_index else []) + cells)
    return {"kind": "table", "columns": cols, "rows": rows, "total": int(total), "indexed": bool(named_index)}, head

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--notebook", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--csv"); ap.add_argument("--label", default="")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    if a.csv: os.environ["LOCAL_CSV"] = a.csv
    os.environ.setdefault("MPLBACKEND", "Agg")
    warnings.filterwarnings("ignore")
    import matplotlib; matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.show = lambda *x, **k: None
    # Phông có dấu tiếng Việt nếu có
    plt.rcParams["font.family"] = "DejaVu Sans"

    nb = json.load(open(a.notebook, encoding="utf-8"))
    ns = {"__name__": "__main__"}
    cells, ipy_cells, failed, n = [], [], None, 0
    t_all = time.time()

    for c in nb["cells"]:
        src = "".join(c["source"])
        if c["cell_type"] == "markdown":
            cells.append({"type": "markdown", "source": src})
            ipy_cells.append({"cell_type": "markdown", "metadata": {}, "source": c["source"]})
            continue
        n += 1
        outs, ipy_outs, ms = [], [], None
        if failed is None:
            buf, val, err = io.StringIO(), None, None
            t0 = time.time()
            try:
                tree = ast.parse(src); last = None
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    last = ast.Expression(tree.body.pop().value)
                with contextlib.redirect_stdout(buf):
                    exec(compile(tree, "<cell>", "exec"), ns)
                    if last is not None: val = eval(compile(last, "<cell>", "eval"), ns)
            except Exception:
                err = traceback.format_exc(limit=-4)
            ms = int((time.time() - t0) * 1000)
            text = buf.getvalue()
            if text:
                outs.append({"kind": "stream", "text": text[:MAX_TEXT]})
                ipy_outs.append({"output_type": "stream", "name": "stdout", "text": text[:MAX_TEXT].splitlines(True)})
            for num in plt.get_fignums():
                fig = plt.figure(num); b = io.BytesIO()
                fig.savefig(b, format="png", dpi=110, bbox_inches="tight")
                png = base64.b64encode(b.getvalue()).decode()
                outs.append({"kind": "image", "png": png})
                ipy_outs.append({"output_type": "display_data", "data": {"image/png": png, "text/plain": ["<Figure>"]}, "metadata": {}})
                plt.close(fig)
            if val is not None and err is None:
                try:
                    import pandas as pd
                    if isinstance(val, (pd.DataFrame, pd.Series)):
                        tbl, head = to_table(val); outs.append(tbl)
                        ipy_outs.append({"output_type": "execute_result", "execution_count": n, "metadata": {},
                                         "data": {"text/plain": repr(head).splitlines(True), "text/html": head.to_html().splitlines(True)}})
                    else:
                        t = repr(val)[:MAX_TEXT]; outs.append({"kind": "text", "text": t})
                        ipy_outs.append({"output_type": "execute_result", "execution_count": n, "metadata": {}, "data": {"text/plain": t.splitlines(True)}})
                except Exception:
                    pass
            if err:
                failed = {"cell": n, "error": err}
                outs.append({"kind": "error", "text": err})
                ipy_outs.append({"output_type": "error", "ename": "Error", "evalue": err.strip().splitlines()[-1], "traceback": err.splitlines()})
        cells.append({"type": "code", "n": n, "source": src, "outputs": outs, "ms": ms})
        ipy_cells.append({"cell_type": "code", "execution_count": n if ms is not None else None, "metadata": {},
                          "source": c["source"], "outputs": ipy_outs})

    df = ns.get("df")
    meta = {"label": a.label, "source": str(ns.get("SOURCE", "")), "rows": int(len(df)) if df is not None else None,
            "duration": round(time.time() - t_all, 1), "finishedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "ok": failed is None, "error": failed}
    json.dump({"meta": meta, "cells": cells}, open(os.path.join(a.out, "result.json"), "w", encoding="utf-8"), ensure_ascii=False)
    nb_out = {"cells": ipy_cells, "metadata": nb.get("metadata", {}), "nbformat": 4, "nbformat_minor": 4}
    json.dump(nb_out, open(os.path.join(a.out, "executed.ipynb"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(meta, ensure_ascii=False))
    sys.exit(0 if failed is None else 1)

if __name__ == "__main__":
    main()
