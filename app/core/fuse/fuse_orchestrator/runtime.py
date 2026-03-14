def get_runtime_module():
    """Return the fuse_orchestrator package as a runtime dependency namespace."""
    import app.core.fuse.fuse_orchestrator as mounts_module

    return mounts_module
