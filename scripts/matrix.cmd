@echo off
for %%P in (nmap-connect-scan.pcap sqlmap-sqli.pcap) do (
  del /q output\suricata\* >nul 2>&1
  set "PCAP=%%P"
  docker compose --profile detect run --rm suricata >nul 2>&1
  echo === %%P ===
  find /c "1000001" output\suricata\fast.log
  find /c "1000002" output\suricata\fast.log
)