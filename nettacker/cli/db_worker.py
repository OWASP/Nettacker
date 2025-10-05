import argparse
import signal
import time

from nettacker.database.writer import get_writer


def _handle_sig(signum, frame):
    writer = get_writer()
    writer.stop()


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Drain the queue once and exit")
    parser.add_argument("--batch-size", type=int, default=None, help="Writer batch size")
    parser.add_argument("--interval", type=float, default=None, help="Writer sleep interval")
    parser.add_argument(
        "--max-items", type=int, default=None, help="Max items to process in --once mode"
    )
    parser.add_argument("--summary", action="store_true", help="Print a summary after --once")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    # apply runtime config
    from nettacker.database.writer import get_writer_configured, get_stats

    writer = get_writer_configured(batch_size=args.batch_size, interval=args.interval)
    if args.once:
        processed = writer.drain_once(max_iterations=args.max_items or 100000)
        if args.summary:
            stats = get_stats()
            print(
                f"processed={processed} total_processed={stats.get('processed')} queue_size={stats.get('queue_size')}"
            )
        return

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        writer.stop()


if __name__ == "__main__":
    run()
