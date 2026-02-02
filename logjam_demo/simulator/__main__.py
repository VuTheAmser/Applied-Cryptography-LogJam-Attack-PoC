import sys
import argparse

# Force unbuffered output for real-time display
sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, 'reconfigure') else None

from .handshake import run_demo


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="LogJam Attack Demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m logjam_demo.simulator
  python -m logjam_demo.simulator --username bob --password secret123
        """
    )
    
    parser.add_argument(
        '--username',
        type=str,
        default='alice',
        help='Username for demo HTTP request (default: alice)'
    )
    
    parser.add_argument(
        '--password',
        type=str,
        default='p@ssw0rd',
        help='Password for demo HTTP request (default: p@ssw0rd)'
    )
    
    args = parser.parse_args()
    
    try:
        run_demo(username=args.username, password=args.password)
    except KeyboardInterrupt:
        print("\n\n[DEMO] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[ERROR] Demo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

