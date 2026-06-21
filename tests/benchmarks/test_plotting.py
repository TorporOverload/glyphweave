from benchmarks import plotting


def test_setup_style_and_save(tmp_path, monkeypatch):
    monkeypatch.setattr(plotting, "FIG_DIR", tmp_path)
    plotting.setup_style()
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots()
    ax.plot([1, 2, 3], [1, 4, 9])
    pdf, png = plotting.save(fig, "demo")
    assert pdf.exists() and png.exists()
    assert pdf.stat().st_size > 0
