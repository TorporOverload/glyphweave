import sys


from app.utils.logging import DEBUG_ENABLED, logger

def main() -> int:
    """Main entry point."""
    logger.debug("GlyphWeave starting...")

    if DEBUG_ENABLED:
        logger.debug("Debug mode enabled")

    print("GlyphWeave v0.1.0")

    return 0


if __name__ == "__main__":
    sys.exit(main())
