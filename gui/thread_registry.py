"""Preprost register primerkov QThread za urejeno zaustavitev."""
import logging

logger = logging.getLogger(__name__)

_registry = []


def register(thread) -> None:
    try:
        _registry.append(thread)
    except Exception:
        pass


def stop_all(timeout: int = 2000) -> None:
    """Poskusi končati in počakaj na vse registrirane niti QThread.

    Doda osnovno beleženje za lažje odkrivanje niti, ki ostanejo aktivne
    med zaustavitvijo tolmača.
    """
    for t in list(_registry):
        try:
            if t is None:
                continue
            name = getattr(t, 'objectName', lambda: None)()
            try:
                if hasattr(t, 'isRunning') and t.isRunning():
                    logger.debug("Stopping QThread: %s", getattr(t, 'objectName', lambda: repr(t))())
                    try:
                        t.quit()
                    except Exception:
                        logger.debug("QThread.quit() raised", exc_info=True)
                    try:
                        t.wait(timeout)
                    except Exception:
                        logger.debug("QThread.wait() raised or timed out", exc_info=True)
                    logger.debug("QThread stopped (or timed out): %s", getattr(t, 'objectName', lambda: repr(t))())
            except Exception:
                logger.debug("Error while stopping thread", exc_info=True)
        except Exception:
            logger.debug("Unexpected error in stop_all", exc_info=True)


def clear():
    _registry.clear()
