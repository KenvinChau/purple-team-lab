@echo off
for %%P in (nmap-connect-scan.pcap sqlmap-sqli.pcap benign-browsing.pcap) do (
  del /q output\suricata\* >nul 2>&1
  set "PCAP=%%P"
  docker compose --profile detect run --rm suricata >nul 2>&1
  echo === %%P ===
  for %%S in (1000001 1000002 1000003) do (
    <nul set /p "=%%S: "
    find /c "%%S" output\suricata\fast.log
  )
)