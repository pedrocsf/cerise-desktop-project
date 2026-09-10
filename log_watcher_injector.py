import os
import sys

from log_watcher import RagRetriever, PROMPT_TEMPLATE, format_rag_block, build_process_tree_block
from llama import send_for_analysis


def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def show_header():
    clear_screen()
    print(" > CERISE <")
    print("Type your log input below. Type 'exit' or 'quit' to stop.")
    print("-" * 40)


def emit_line(message):
    sys.stdout.write(f"\r\033[K{message}\n")
    sys.stdout.flush()


def print_block(tag, title, content):
    emit_line(f"[{tag}] {title}")
    for block_line in content.splitlines():
        emit_line(f"      {block_line}")


def main():
    show_header()

    rag_retriever = RagRetriever()

    try:
        while True:
            user_input = input("\n[INPUT] Enter log content (or 'exit'/'quit' to stop): ").strip()

            if user_input.lower() in ['exit', 'quit']:
                break

            if not user_input:
                emit_line("[INFO] Input is empty. Please enter some log content.")
                continue

            emit_line(f"\n[USER] Processing input: '{user_input}'")

            retrieval = rag_retriever.retrieve_context(user_input)
            if retrieval.get("hyde_degraded"):
                emit_line("[HyDE degradado] resumo de reescrita indisponível, retrieval usou o log bruto")
            print_block("RAG", "Context retrieved", format_rag_block(retrieval))

            full_prompt = PROMPT_TEMPLATE.format(
                rag_context=format_rag_block(retrieval),
                process_tree=build_process_tree_block(user_input.splitlines()),
                log_content=user_input,
            )

            emit_line("[AI] Starting analysis...")
            analysis = send_for_analysis(full_prompt)
            if analysis:
                print_block("AI", "Analysis result", analysis)
            else:
                emit_line("[AI] No analysis result received.")

    except KeyboardInterrupt:
        emit_line("\n[INFO] Exiting interactive analyzer.")
    except Exception as e:
        emit_line(f"\n[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
