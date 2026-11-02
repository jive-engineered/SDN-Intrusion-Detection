#!/usr/bin/env python3
import http.server
import socketserver
import json
import os
import subprocess

PORT = 8080

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SDN-IDS Real-Time Defense Dashboard</title>
    <meta http-equiv="refresh" content="3">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { color: #38bdf8; font-size: 26px; border-bottom: 2px solid #1e293b; padding-bottom: 12px; margin-bottom: 20px; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 13px; font-weight: 600; text-transform: uppercase; }
        .badge-active { background: #065f46; color: #34d399; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: #1e293b; border-radius: 8px; padding: 18px; border: 1px solid #334155; }
        .card h3 { margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; color: #94a3b8; }
        .metric { font-size: 22px; font-weight: bold; color: #f1f5f9; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; font-size: 13px; }
        th { background: #0f172a; color: #94a3b8; font-weight: 600; }
        tr:hover { background: #243247; }
        .danger { color: #f87171; font-weight: bold; }
        .success { color: #4ade80; font-weight: bold; }
        pre { background: #0b1120; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #e2e8f0; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h1>SDN-IDS Live Defense Panel</h1>
            <span class="badge badge-active">Controller Active</span>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Protected Switch</h3>
                <div class="metric">s1 (OpenFlow 1.3)</div>
            </div>
            <div class="card">
                <h3>Mitigation Status</h3>
                <div class="metric success">Active Ingress Quarantine</div>
            </div>
            <div class="card">
                <h3>Monitored Attack Vector</h3>
                <div class="metric danger">Multi-IP Spoofing</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 20px;">
            <h3>Active OpenFlow 1.3 Flow Rules on Switch s1</h3>
            <pre>__FLOWS_DATA__</pre>
        </div>

        <div class="card">
            <h3>Configured IDS Rules</h3>
            <pre>__RULES_DATA__</pre>
        </div>
    </div>
</body>
</html>
"""

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()

            # Fetch active OpenFlow rules
            try:
                flows = subprocess.check_output(
                    ['ovs-ofctl', 'dump-flows', 's1', '-O', 'OpenFlow13'],
                    stderr=subprocess.STDOUT
                ).decode('utf-8')
            except Exception as e:
                flows = f"Waiting for switch flows: {e}"

            # Fetch ids_rules.json
            rules_path = os.path.join(os.path.dirname(__file__), '../controller/ids_rules.json')
            try:
                with open(rules_path, 'r') as rf:
                    rules = json.dumps(json.load(rf), indent=2)
            except Exception as e:
                rules = f"Could not load rules: {e}"

            content = HTML_PAGE.replace('__FLOWS_DATA__', flows).replace('__RULES_DATA__', rules)
            self.wfile.write(content.encode('utf-8'))
        else:
            self.send_error(404, "Page not found")

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
        print(f"Dashboard running on http://127.0.0.1:{PORT}")
        httpd.serve_forever()
