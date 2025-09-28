<h1>SOC Project Documentation: Splunk & Windows Red Team Lab</h1>
<hr>

<h2>1. Executive Summary</h2>
<p>
  This project demonstrates the setup of a <strong>Security Operations Center (SOC) lab environment</strong> designed to detect malicious activities. 
  The lab leverages <strong>Splunk Enterprise</strong> hosted on an <strong>Ubuntu server</strong> and a <strong>Windows machine</strong> configured to simulate 
  red team attack techniques. The primary objective is to capture adversarial behaviors in Splunk and analyze the telemetry for detection and response.
</p>

<hr>

<h2>2. Introduction / Background</h2>
<p>Effective SOC operations rely on visibility into endpoint activities and the ability to detect malicious behaviors. 
This project was undertaken to:</p>
<ul>
  <li>Gain hands-on experience with SIEM tools (<strong>Splunk</strong>).</li>
  <li>Understand <strong>red team attack simulations</strong> and their impact on endpoints.</li>
  <li>Practice configuring <strong>logging and telemetry collection</strong> from Windows.</li>
  <li>Build <strong>detection logic</strong> and validate it with real attack data.</li>
</ul>

<hr>

<h2>3. Environment Setup</h2>
<ul>
  <li><strong>Splunk Server</strong>: Ubuntu Server hosting Splunk Enterprise.</li>
  <li><strong>Endpoint</strong>: Windows OS configured with Sysmon and event forwarding.</li>
  <li><strong>Red Team Tests</strong>: Malicious commands and techniques executed on Windows.</li>
</ul>

<hr>

<h2>4. Red Team Simulations</h2>
<p>Red team techniques executed on Windows included:</p>
<ul>
  <li>Command & Scripting Interpreter (<strong>PowerShell</strong>).</li>
  <li>Create Account (<strong>Local Account</strong>).</li>
  <li>Modify Registry.</li>
</ul>
<p>These were mapped to <strong>MITRE ATT&amp;CK techniques</strong> for standardization.</p>

<hr>

<h2>5. Data Collection / Logging Configuration</h2>
<ul>
  <li><strong>Sysmon</strong> installed on Windows endpoint to capture detailed telemetry (process creation, command-line arguments, network connections).</li>
  <li><strong>Windows Event Forwarding</strong> configured to forward events to Splunk.</li>
  <li><strong>Splunk Universal Forwarder</strong> used for log collection and ingestion.</li>
</ul>

<hr>

<h2>6. Detection &amp; Analysis (Splunk Queries &amp; Results)</h2>
<p>Splunk searches were created to identify malicious behavior.</p>

<h3>Queries, Screenshots, Results</h3>

<p><strong>Detect PowerShell script execution:</strong></p>
<pre>
index=endpoint host=target CommandLine="*powershell*"
</pre>
<h3>Screenshots</h3>
<img width="788" height="569" alt="powershell-1" src="https://github.com/user-attachments/assets/2146b6d0-0ac4-4f53-8389-ad43b3c08ec2" />

<h3>Results:</h3>
<ul>
  <li>Detection: Splunk captured a Sysmon ProcessCreate event showing powershell.exe execution, including key fields like _time, host, user, ParentImage, CommandLine, and SHA256 hashes, confirming the detection pipeline is working.</li>
  <li>Triage / Analysis: Enables investigation by inspecting command arguments, parent process, network activity, and file hashes to determine whether the execution is benign or malicious.</li>
</ul>
<br>
<p><strong>Detect Local Account Creation (Windows Security):</strong></p>
<pre>
index=endpoint host=target technqiue_id=T1018 user="NewLocalUser"
</pre>
<h3>Screenshots</h3>
<img width="785" height="568" alt="usercreation" src="https://github.com/user-attachments/assets/79701357-6b20-4c66-917b-e858f61c6b34" />

<h3>Results:</h3>
<ul>
  <li>A high-integrity process (Code.exe) was launched by a local user under suspicious conditions, indicating potential misuse of elevated privileges.</li>
  <li>This event may indicate unauthorized software execution with elevated privileges, potentially used as a precursor to system tampering actions such as local account creation.</li>
</ul>
<br>
<p><strong> Detect Registry Modifications (Windows Security &amp; Sysmon Registry events):</strong></p>
<pre>
index=endpoint host=target technique_id=T1547.001 "Registry*"
</pre>
<h3>Screenshots</h3>
<img width="790" height="540" alt="registrykey" src="https://github.com/user-attachments/assets/abe5b12f-6d23-4d87-8ac1-2c7ed9ad1dac" />

<h3>Results:</h3>
<ul>
  <li>Registry Modification Detected: A high-integrity process (reg.exe) executed by cmd.exe modified the Windows registry to add a new autorun entry under HKCU\Software\Microsoft\Windows\CurrentVersion\Run, indicating potential persistence setup.</li>
  <li>Execution Under SYSTEM Context: The process ran under NT AUTHORITY\SYSTEM, suggesting elevated privileges and possible unauthorized system-level activity.</li>
  <li>Suspicious Parent-Child Process Chain: The parent process (cmd.exe) invoked reg.exe with a crafted command line, which may indicate script-based tampering or automated deployment of persistence mechanisms.</li>
</ul>

<hr>

<h2>8. Conclusion &amp; Next Steps</h2>
<p>This SOC lab project demonstrated:</p>
<ul>
  <li>End-to-end <strong>log ingestion and detection</strong> using Splunk.</li>
  <li>Execution of <strong>red team techniques</strong> and their capture in telemetry.</li>
  <li>Basic <strong>detection engineering</strong> through Splunk queries.</li>
</ul>

<p><strong>Next Steps:</strong></p>
<ul>
  <li>Expand detection coverage (more <strong>MITRE ATT&amp;CK techniques</strong>).</li>
  <li>Build <strong>Splunk dashboards</strong> for continuous monitoring.</li>
  <li>Automate alerts and integrate with <strong>SOAR</strong> for response.</li>
</ul>

<hr>
