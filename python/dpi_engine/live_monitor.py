import argparse
import sys
import signal
from dpi_engine import SnifferStream, DpiFilter, Proto

def main():
    parser = argparse.ArgumentParser(description="Kernel-Bypass DPI Live Network & Application Request Monitor")
    parser.add_argument("--app", type=str, help="Filter by executable name (e.g. chrome.exe, telegram.exe)")
    parser.add_argument("--pid", type=int, help="Filter by Process ID")
    parser.add_argument("--path", type=str, help="Filter by substring in application path")
    parser.add_argument("--domain", type=str, help="Filter by domain/SNI substring (e.g. google, discord)")
    parser.add_argument("--exclude", type=str, help="Exclude application name")
    parser.add_argument("--pcap", type=str, help="Replay from PCAP dump instead of live NIC")
    parser.add_argument("--filter", type=str, default="outbound && (tcp.DstPort == 80 || tcp.DstPort == 443 || udp.DstPort == 53)", help="WinDivert BPF capture filter")
    args = parser.parse_args()

    print("\033[1;36m========================================================================================\033[0m")
    print("\033[1;36m   Kernel-Bypass DPI Streamer — Live Network & Application Request Monitor (Python)    \033[0m")
    print("\033[1;36m========================================================================================\033[0m")
    if args.app:
        print(f"\033[33mFiltering by Application:\033[0m {args.app}")
    if args.domain:
        print(f"\033[33mFiltering by Domain:\033[0m {args.domain}")

    print("\033[1;37m{:<12} {:<18} {:<8} {:<30} {:<28} {}\033[0m".format(
        "TIME", "PROCESS [PID]", "PROTO", "REMOTE TARGET", "DOMAIN / SNI / QUERY", "DETAILS"
    ))
    print("-" * 105)

    stream = SnifferStream(
        target=args.pcap or args.filter,
        is_pcap=bool(args.pcap),
        app=args.app,
        pid=args.pid,
        path_contains=args.path,
        exclude_app=args.exclude,
    )

    filt = DpiFilter()
    if args.domain:
        filt.domain_contains(args.domain)

    try:
        for req in stream.stream_requests():
            if not filt.matches(req):
                continue

            app_str = f"{req['app']} [{req['pid']}]" if req['pid'] else req['app']
            proto_color = "\033[33m" if req['proto'] == "TLS" else ("\033[34m" if req['proto'] == "DNS" else "\033[31m")
            details = ""
            if req.get("ja3"):
                details = f"\033[90mJA3:{req['ja3'][:10]}...\033[0m"
            elif req.get("dns_answers"):
                details = f"\033[36m-> {req['dns_answers'][0]}\033[0m"
            elif req.get("http_method"):
                details = f"{req['http_method']} {req.get('http_uri', '')[:30]}"

            print("{:<12} \033[32m{:<18}\033[0m {}{:<8}\033[0m {:<30} \033[1;35m{:<28}\033[0m {}".format(
                req["time"],
                app_str[:17],
                proto_color,
                req["proto"],
                f"port:{req['target_port']}",
                req["domain"][:27],
                details
            ))
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[Monitor] Stopped by operator.")

if __name__ == "__main__":
    main()
