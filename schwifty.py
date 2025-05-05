from core.scanner_engine import ScannerEngine
import argparse
import sys
import logging
from core.scanner_engine import ScannerEngine
from utils.reporter import VulnerabilityReporter

def main():
    parser = argparse.ArgumentParser(description="WubbaHack-a-Tron 9000: Interdimensional Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-x", "--xss", action="store_true")
    parser.add_argument("-s", "--sqli", action="store_true")
    parser.add_argument("-c", "--csrf", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    print(r""" _____      _             _  __ _         _____                                 
/  ___|    | |           (_)/ _| |       /  ___|                                
\ `--.  ___| |____      ___| |_| |_ _   _\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
 `--. \/ __| '_ \ \ /\ / / |  _| __| | | |`--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
/\__/ / (__| | | \ V  V /| | | | |_| |_| /\__/ / (_| (_| | | | | | | |  __/ |   
\____/ \___|_| |_|\_/\_/ |_|_|  \__|\__, \____/ \___\__,_|_| |_|_| |_|\___|_|   
                                     __/ |                                      
                                    |___/                                       
""")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=log_level
    )

    try:
        logging.info(f"Starting security scan for {args.url}")
        engine = ScannerEngine(args.url)

        results = engine.run_scan({
            'xss': args.xss,
            'sqli': args.sqli,
            'csrf': args.csrf
        })

        reporter = VulnerabilityReporter(results)
        print(reporter.generate_report('console'))

    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()