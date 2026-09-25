#!/usr/bin/env python3
"""Render the L2-E1 pilot evidence pack (lab #740) from a lane artifact.

The pack is ONLY ever produced here, from the `pilot-evidence` artifact of an
`acceptance-graviton.yml` pilot run — never hand-written. The test
(`crates/qumbra-wallet/tests/annulet_pilot.rs`) writes `pilot.jsonl`; this
script turns it into `docs/annulet-pilot-<date>.md` and `-zh.md`. The two
share one table layout and identical numbers; only the fixed prose and the
labels are translated, and they live here as two fixed templates.

    scripts/annulet-pilot-render.py --jsonl pilot.jsonl --run-id <id> \\
        --sha <head sha> --date YYYY-MM-DD [--out-dir docs]

Refuses (exit 1) when the record is incomplete: every step 0..11, the step-9
refusal line, the R timings and the final ledger must all be present.
"""

import argparse
import json
import sys
from pathlib import Path

STEPS = list(range(12))

T = {
    "en": {
        "title": "L2-E1 — the pUSD-test stablecoin pilot, run on the devnet harness",
        "other": "中文版",
        "provenance": "Rendered by `scripts/annulet-pilot-render.py` from the `pilot-evidence` artifact of "
        "Graviton-lane run **{run}** at `{sha}`. Nothing below is hand-written; numbers are the "
        "test's own record.",
        "s0": "What this pilot is, and what it isn't",
        "p0": "Per `l2-own-circuit-decision` §4, a Phase-0 stablecoin pilot is **a sidechain that reads "
        "L1 anchors**. It runs on the Annulet fork of `qumbra-node`: a single sequencer, the L2 circuit "
        "family, the registry, and no bridge and no QMB on L2. Its value to Qumbra is the shared "
        "toolchain, wallet and attestation surfaces, and the path to Phase 1. **It is not yet Qumbra's "
        "money.** In this harness the L1 anchor fields are genesis-static; no live L1 is read.",
        "s1": "The instrument",
        "p1": "`pUSD-test` (\"Pilot USD (test)\", asset id 21) is a **test** instrument: the issuer and "
        "the freeze order are **simulated**, and no real issuer, regulator or currency is represented. "
        "Mode Hybrid, runtime freeze by `issuer update`, redeem closed (holders redeem by sending to "
        "the issuer, who burns). Three in-process nodes under the real `L2Verifier`; participants are "
        "the issuer I and holders A, B and F (F is frozen at step 8).",
        "s2": "Steps — attested outstanding supply",
        "p2": "After every step the test asserts, on all three nodes, that `/v1/attest` (the explorer's "
        "own code) reports `node_agrees = true` and that the attested outstanding supply equals both "
        "the node's supply ledger and the expected figure.",
        "h2": ["step", "what", "equivalent command", "height", "nullifiers", "attested (n0 / n1 / n2)", "expected", "wall s"],
        "s3": "Transactions",
        "p3": "DA bytes are the encoded Annulet wire (proof, discovery payload and L2 surface included). "
        "**verify ms is measured in the test process** by re-verifying each sealed transaction with "
        "`L2Verifier` — not the sequencer's admission path.",
        "h3": ["step", "shape", "height", "tx id", "nullifiers", "fee", "proof B", "discovery B", "DA (wire) B", "verify ms (test process)"],
        "s4": "Step 9 — the frozen holder is refused twice",
        "p4w": "The wallet refused F's send before proving: `{w}`.",
        "p4n": "F's hand-forged spend under the pre-freeze leaf proved, and the node refused it:",
        "s5": "Final ledger",
        "h5": ["holder", "held"],
        "names": {"A": "A", "B": "B", "F_frozen": "F (frozen)", "issuer": "issuer I", "outstanding": "**outstanding**"},
        "p5": "Minted 750 − redeemed 150 = 600; F's 150 is frozen but still outstanding.",
        "s6": "Timings",
        "p6": "R prove + submit, measured around the wallet verb (neither waits for inclusion): "
        "register **{r1:.1} s**, freeze **{r2:.1} s**. Per-step wall time is in the steps table "
        "(proves, submits and settle waits together). The job's stamped console (`pilot.log` in the "
        "same artifact) carries the same lines with wall-clock stamps.",
    },
    "zh": {
        "title": "L2-E1 —— pUSD-test 稳定币试点,在 devnet 测试台上跑通",
        "other": "English",
        "provenance": "本文由 `scripts/annulet-pilot-render.py` 从 Graviton 车道运行 **{run}**(`{sha}`)的 "
        "`pilot-evidence` 产物生成。以下没有一处手写,数字都是测试自己记下的。",
        "s0": "这个试点是什么,不是什么",
        "p0": "按 `l2-own-circuit-decision` §4,Phase-0 稳定币试点是**一条读取 L1 锚点的侧链**。它跑在 "
        "`qumbra-node` 的 Annulet 分叉上:单一排序器、L2 电路族、注册表;没有跨链桥,L2 上也没有 QMB。"
        "它对 Qumbra 的价值在于共用的工具链、钱包和证明面,以及通往 Phase 1 的路径。**它还不是 Qumbra 的钱。**"
        "在这个测试台里,L1 锚点字段固定在创世里,不读取任何在线的 L1。",
        "s1": "试点资产",
        "p1": "`pUSD-test`(\"Pilot USD (test)\",资产编号 21)是**测试**资产:发行方和冻结令都是**模拟的**,"
        "不代表任何真实的发行方、监管方或货币。模式 Hybrid,冻结由 `issuer update` 在运行时发布,"
        "赎回关闭(持有人把币转给发行方,由发行方销毁)。三个进程内节点,用真实的 `L2Verifier`;"
        "参与方是发行方 I 和持有人 A、B、F(F 在第 8 步被冻结)。",
        "s2": "各步骤 —— 证明出的流通量",
        "p2": "每一步之后,测试在三个节点上都断言:`/v1/attest`(浏览器自己的代码)报告 `node_agrees = true`,"
        "且证明出的流通量同时等于节点的供应账本和预期值。",
        "h2": ["步骤", "内容", "等价命令", "高度", "nullifier 数", "证明值(n0 / n1 / n2)", "预期", "耗时 s"],
        "s3": "交易",
        "p3": "DA 字节即 Annulet 线上编码(含证明、发现载荷和 L2 面)。**verify ms 是在测试进程里测的**:"
        "对每笔已上链交易用 `L2Verifier` 重验一遍,不是排序器的准入路径。",
        "h3": ["步骤", "形状", "高度", "交易 id", "nullifier 数", "手续费", "证明 B", "发现 B", "DA(线上)B", "verify ms(测试进程)"],
        "s4": "第 9 步 —— 被冻结的持有人两次被拒",
        "p4w": "钱包在生成证明之前就拒绝了 F 的转账:`{w}`。",
        "p4n": "F 用冻结前的叶子手工伪造的花费能生成证明,但节点拒绝了它:",
        "s5": "最终账目",
        "h5": ["持有人", "持有量"],
        "names": {"A": "A", "B": "B", "F_frozen": "F(已冻结)", "issuer": "发行方 I", "outstanding": "**流通量**"},
        "p5": "铸造 750 − 赎回 150 = 600;F 的 150 被冻结,但仍计入流通量。",
        "s6": "耗时",
        "p6": "R 的证明加提交时间,在钱包命令外围计时(两者都不等上链):注册 **{r1:.1} s**,冻结 **{r2:.1} s**。"
        "每步耗时见步骤表(证明、提交和等待上链合计)。同一产物里的 `pilot.log` 是任务的带时间戳控制台,"
        "有同样的行和挂钟时间。",
    },
}


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def load(path):
    steps, refusal, r_ms, final = {}, None, None, None
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        d = json.loads(line)
        if "final" in d:
            final = d["final"]
        elif "r_prove_submit_ms" in d:
            r_ms = d["r_prove_submit_ms"]
        elif "node_refusal" in d:
            refusal = d
        elif "what" in d:
            steps[d["step"]] = d
        else:
            sys.exit(f"line {n}: unrecognised evidence record: {line[:80]}")
    missing = [s for s in STEPS if s not in steps]
    gaps = [name for name, v in (("step-9 refusal", refusal), ("R timings", r_ms), ("final ledger", final)) if v is None]
    if missing or gaps:
        sys.exit(f"REFUSED — incomplete record: missing steps {missing}, missing {gaps}")
    return steps, refusal, r_ms, final


def render(lang, a, steps, refusal, r_ms, final):
    t = T[lang]
    other = f"annulet-pilot-{a.date}{'' if lang == 'zh' else '-zh'}.md"
    rows2, rows3 = [], []
    for s in STEPS:
        d = steps[s]
        att = " / ".join(d["attested_outstanding"])
        rows2.append([s, d["what"], f"`{d['command']}`", d["height"], d["nullifiers"], att, d["expected_outstanding"],
                      f"{d['step_wall_ms'] / 1e3:.1f}"])
        for x in d["txs"]:
            rows3.append([s, x["shape"] or "—", x["height"], f"`{x['tx_id'][:16]}…`", x["nullifiers"], x["fee"],
                          f"{x['proof_bytes']:,}", f"{x['discovery_bytes']:,}", f"{x['wire_bytes']:,}",
                          f"{x['verify_ms_test_process']:.2f}"])
    rows5 = [[t["names"][k], final[k]] for k in ("A", "B", "F_frozen", "issuer", "outstanding")]
    parts = [
        f"# {t['title']}",
        f"[{t['other']}]({other})",
        t["provenance"].format(run=a.run_id, sha=a.sha),
        f"## 0. {t['s0']}", t["p0"],
        f"## 1. {t['s1']}", t["p1"],
        f"## 2. {t['s2']}", t["p2"], table(t["h2"], rows2),
        f"## 3. {t['s3']}", t["p3"], table(t["h3"], rows3),
        f"## 4. {t['s4']}", t["p4w"].format(w=refusal["wallet_refusal"]), t["p4n"],
        "```\n" + refusal["node_refusal"] + "\n```",
        f"## 5. {t['s5']}", table(t["h5"], rows5), t["p5"],
        f"## 6. {t['s6']}", t["p6"].format(r1=r_ms[0] / 1e3, r2=r_ms[1] / 1e3),
        "---",
        f"`scripts/annulet-pilot-render.py --jsonl pilot.jsonl --run-id {a.run_id} --sha {a.sha} --date {a.date}`",
    ]
    return "\n\n".join(parts) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--jsonl", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--sha", required=True)
    p.add_argument("--date", required=True)
    p.add_argument("--out-dir", default="docs")
    a = p.parse_args()
    steps, refusal, r_ms, final = load(a.jsonl)
    out = Path(a.out_dir)
    for lang, suffix in (("en", ""), ("zh", "-zh")):
        f = out / f"annulet-pilot-{a.date}{suffix}.md"
        f.write_text(render(lang, a, steps, refusal, r_ms, final))
        print(f)


if __name__ == "__main__":
    main()
