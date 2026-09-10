

import argparse
import json
import os
import re
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "virtual_machine"))

from log_watcher import RagRetriever, PROMPT_TEMPLATE, format_rag_block, build_process_tree_block
from pipeline_web import state, send_to_llm, _llm_sync

BATCH_DIR = os.path.join(BASE_DIR, "synthetic_batches")
RUBRIC_FILE = os.path.join(BASE_DIR, "rubric.md")
SECRETS = {
    "claude": os.path.join(BASE_DIR, "secrets", "claude.txt"),
    "openai": os.path.join(BASE_DIR, "secrets", "gpt.txt"),
    "gemini": os.path.join(BASE_DIR, "secrets", "gemini.txt"),
}


def load_titles():
    titles = {}
    if os.path.exists(RUBRIC_FILE):
        for line in open(RUBRIC_FILE, encoding="utf-8"):
            m = re.match(r"^## Batch (\d{4})\s*—\s*(.+)$", line.strip())
            if m:
                titles[int(m.group(1))] = m.group(2).strip()
    return titles


def load_batches():
    out = []
    for name in sorted(os.listdir(BATCH_DIR)):
        m = re.match(r"batch_(\d{4})\.json$", name)
        if not m:
            continue
        with open(os.path.join(BATCH_DIR, name), encoding="utf-8") as f:
            data = json.load(f)
        out.append((int(m.group(1)), "\n".join(data["events"][-100:])))
    return out


def analyse(prompt):
    result = {}
    send_to_llm(
        prompt,
        lambda _token: None,
        lambda text, err: result.update({"text": text, "err": err}),
    )
    return result.get("text"), result.get("err")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--provider", required=True, choices=["ollama", "openai", "gemini", "claude"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--label", help="nome do agente no relatório (padrão: provider/model)")
    ap.add_argument("--out", default="rag_test_results_v2.md")
    ap.add_argument("--retrieval-only", action="store_true",
                    help="só HyDE + retrieval, sem chamar a análise final")
    ap.add_argument("--sleep", type=float, default=2.0, help="pausa entre batches, em segundos")
    args = ap.parse_args()

    api_key = ""
    if args.provider in SECRETS:
        path = SECRETS[args.provider]
        if not os.path.exists(path):
            raise SystemExit(f"[ERRO] chave não encontrada em {path}")
        api_key = open(path, encoding="utf-8").read().strip()

    state.llm_config = {"provider": args.provider, "model": args.model, "api_key": api_key}
    label = args.label or f"{args.provider}/{args.model}"

    print(f"provedor: {args.provider} · modelo: {args.model}")
    print("HyDE e análise final usam o mesmo modelo.\n")

    hyde_out = {}

    def hyde_recording(prompt):
        texto = _llm_sync(prompt)
        hyde_out["last"] = texto
        return texto

    retriever = RagRetriever(hyde_llm=hyde_recording)
    if retriever.collection is None:
        raise SystemExit("[ERRO] RAG indisponível. Rode indexer.py antes.")

    titles = load_titles()
    blocos = []

    for batch_id, batch_data in load_batches():
        titulo = titles.get(batch_id, "")
        print(f"batch {batch_id:04d} — {titulo}")

        hyde_out.clear()
        retrieval = retriever.retrieve_context(batch_data)
        cats = [f"{c['category']}({c['confidence']},{c['score']:.2f})"
                for c in (retrieval.get("candidates") or [])]
        if retrieval.get("hyde_degraded"):
            print("  [HyDE degradado] resumo de reescrita indisponível, retrieval usou o log bruto")
        print(f"  HyDE: {(hyde_out.get('last') or '').strip()[:200].replace(chr(10), ' | ')}")
        print(f"  categorias: {', '.join(cats) or 'nenhuma'}")

        if args.retrieval_only:
            continue

        prompt = PROMPT_TEMPLATE.format(
            rag_context=format_rag_block(retrieval),
            process_tree=build_process_tree_block(batch_data.splitlines()),
            log_content=batch_data,
        )
        t0 = time.time()
        texto, err = analyse(prompt)
        if err or not texto:
            print(f"  [ERRO] {err}")
            texto = f"[ERRO] {err}"
        else:
            print(f"  resposta: {len(texto)} chars em {time.time() - t0:.1f}s")

        hyde_linhas = (hyde_out.get("last") or "").strip().splitlines()
        blocos.append(
            f"## Batch {batch_id:04d} — {titulo}\n"
            f"**RAG categories:** {', '.join(cats) or 'nenhuma'}\n"
            f"**HyDE ({args.provider}/{args.model}):**\n"
            + "".join(f"> {l}\n" for l in hyde_linhas)
            + f"\n```\n{texto}\n```\n"
        )
        time.sleep(args.sleep)

    if args.retrieval_only:
        return

    out_path = os.path.join(BASE_DIR, args.out)
    novo = not os.path.exists(out_path)
    with open(out_path, "a", encoding="utf-8") as f:
        if novo:
            f.write(
                "# Teste comparativo — pipeline RAG (HyDE no mesmo modelo da análise)\n\n"
                "Respostas dos agentes analisando `synthetic_batches/batch_0001..0005.json` através do "
                "pipeline RAG real (`RagRetriever` + `PROMPT_TEMPLATE`), gerado por `run_rag_batches.py`.\n\n"
                "Diferente da primeira rodada, o passo de HyDE usa o **mesmo provedor e modelo** que faz a "
                "análise final, como no `pipeline_web.py`. A reescrita do HyDE de cada batch está registrada "
                "junto das categorias recuperadas.\n\n---\n\n"
            )
        f.write(f"\n# {label}\n\n" + "\n".join(blocos))

    print(f"\ngravado em {out_path}")


if __name__ == "__main__":
    main()
