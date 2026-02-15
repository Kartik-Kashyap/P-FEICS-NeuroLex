from graphviz import Digraph
from pathlib import Path

def figure5_compact(output_dir: str | Path = "."):
    """
    Compact horizontal architecture diagram for research paper
    """
    output_dir = Path("experiment_results")
    output_dir.mkdir(parents=True, exist_ok=True)

    dot = Digraph(name="P-FEICS_Compact", format="png", engine="dot")

    # Tight global layout
    dot.attr(
        rankdir="LR",
        splines="ortho",
        nodesep="0.2",      # smaller horizontal spacing
        ranksep="0.35",      # smaller vertical separation
        margin="0.15,0.15",
        pad="0.1",
    )

    # Compact node style
    dot.attr("node",
        shape="box",
        style="rounded,filled",
        fontname="Arial",
        fontsize="10",       # readable but small
        height="1",
        width="1",
        margin="0.20,0.08",
    )

    dot.attr("edge",
        arrowsize="0.85",
        penwidth="1.4",
        color="#444",
    )

    # ── Nodes (short labels for compactness) ────────────────────────────────
    dot.node("A",  "EEG\nAcquisition",          fillcolor="#e8f5e9")
    dot.node("B",  "AES-256\nEncryption",       fillcolor="#d0eaff")
    dot.node("C1", "DWT\nWatermark",            fillcolor="#fff9e6")
    dot.node("C2", "LSB\nWatermark",            fillcolor="#fff9e6")
    dot.node("D",  ".pfeics\nStorage",          fillcolor="#e0f7fa")
    dot.node("E1", "DWT\nVerification",         fillcolor="#ffebee")
    dot.node("E2", "LSB\nVerification",         fillcolor="#ffebee")
    dot.node("F",  "Combined\nDecision",        fillcolor="#f5f5f5")
    dot.node("G",  "NeuroLex\nAI Explanation",  fillcolor="#e8f5e9")
    dot.node("H",  "PDF\nReport",               fillcolor="#d0eaff")

    # ── Edges ───────────────────────────────────────────────────────────────
    dot.edge("A", "B")
    dot.edge("B", "C1")
    dot.edge("B", "C2")
    dot.edge("C1", "D")
    dot.edge("C2", "D")
    dot.edge("D", "E1")
    dot.edge("D", "E2")
    dot.edge("E1", "F")
    dot.edge("E2", "F")
    dot.edge("F", "G")
    dot.edge("G", "H")

    # Keep parallel steps aligned
    with dot.subgraph() as s:
        s.attr(rank="same")
        s.node("C1")
        s.node("C2")

    with dot.subgraph() as s:
        s.attr(rank="same")
        s.node("E1")
        s.node("E2")

    # ── Output ──────────────────────────────────────────────────────────────
    stem = output_dir / "figure5_compact"
    try:
        dot.render(stem, format="png", cleanup=True)
        dot.render(stem, format="pdf", cleanup=True)
        print(f"Saved compact version:\n  {stem}.png\n  {stem}.pdf")
    except Exception as e:
        print("Rendering failed (likely Graphviz not installed?):", e)
        print("\nPaste this DOT source into an online viewer (e.g. https://dreampuf.github.io/GraphvizOnline/):\n")
        print(dot.source)

    return dot


if __name__ == "__main__":
    figure5_compact()