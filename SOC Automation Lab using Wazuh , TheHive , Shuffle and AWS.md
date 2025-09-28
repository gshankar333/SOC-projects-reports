<h1>SOC Project Documentation: Wazuh, TheHive & Shuffle Automation Lab</h1>
<hr>

<h2>1. Executive Summary</h2>
<p>
  This project demonstrates the setup of a <strong>SOC automation lab environment</strong> designed to detect and respond to malicious activities. 
  The lab leverages <strong>Wazuh Manager</strong> (deployed on AWS) as the SIEM, <strong>TheHive</strong> as the case management platform, and <strong>Shuffle</strong> as the SOAR automation tool. 
  A <strong>local Windows endpoint</strong> was configured with the Wazuh agent to simulate red team attack techniques specifically using <strong>Mimikatz</strong> attack.
  The objective is to validate the end-to-end pipeline from detection to automated enrichment and case creation for improved security operations.
</p>

<hr>

<h2>2. Introduction </h2>
<p>Modern SOC operations require not only detection but also <strong>automation and orchestration</strong> to handle the scale of alerts. 
This project was undertaken to:</p>
<ul>
  <li>Gain hands-on experience with <strong>Wazuh SIEM</strong>.</li>
  <li>Integrate <strong>SOAR workflows</strong> using Shuffle.</li>
  <li>Connect enrichment tools like <strong>VirusTotal</strong> for threat intelligence.</li>
  <li>Implement automated <strong>incident creation and notification</strong> using TheHive and email alerts.</li>
</ul>

<hr>

<h2>3. Environment Setup</h2>
<ul>
  <li><strong>SIEM (Wazuh Manager)</strong>: Deployed on an AWS EC2 instance.</li>
  <li><strong>Case Management (TheHive)</strong>: Deployed on AWS EC2 instance.</li>
  <li><strong>SOAR (Shuffle)</strong>: Cloud-based SOAR tool connected to Wazuh.</li>
  <li><strong>Endpoint</strong>: Windows OS configured with Wazuh Agent.</li>
  <li><strong>Threat Intelligence</strong>: VirusTotal API integrated with Shuffle workflows.</li>
</ul>

<hr>

<h2>4. System Flow</h2>
<img width="601" height="510" alt="soc-project-1 work flow" src="https://github.com/user-attachments/assets/7c2bc6ec-fab9-4b0b-a3bf-75162030d3da" />

<hr>

<h2>5. Data Collection & Logging Configuration</h2>
<p>
  The data collection and logging pipeline in this lab integrates multiple internal components of Wazuh, Shuffle, and TheHive. Each component plays a specific role in ensuring telemetry is collected, processed, stored, analyzed, and escalated for response.
</p>

<h3>5.1 Wazuh Components</h3>
<ul>
  <li><strong>Wazuh Agent</strong>: 
    Installed on the Windows endpoint. It collects telemetry such as process creation, command-line execution, registry changes, and security events. The agent securely forwards this data to the Wazuh Manager over an encrypted channel.
  </li>
  <li><strong>Wazuh Manager</strong>: 
    Central server responsible for receiving logs from all agents. It parses logs, applies decoders and rules, and generates alerts when suspicious activity (like Mimikatz execution) is detected.
  </li>
  <li><strong>Wazuh Indexer (Elasticsearch/OpenSearch)</strong>: 
    Stores all processed alerts and raw events in a scalable search engine. This enables fast querying, historical searches, and correlation across different hosts and events.
  </li>
  <li><strong>Wazuh Dashboard (Kibana-based UI)</strong>: 
    Provides visualization and dashboards for monitoring alerts, system health, and active threats. Analysts can review logs, search events, and validate detections directly through the dashboard.
  </li>
</ul>

<h3>5.2 TheHive Components</h3>
<ul>
  <li><strong>Elasticsearch</strong>: 
    Used by TheHive to index and store cases, alerts, and observables. It ensures quick search and retrieval of incidents during investigation.
  </li>
  <li><strong>Cassandra Database</strong>: 
    Serves as the backend database for TheHive, storing structured data about cases, alerts, observables, and workflow states.
  </li>
  <li><strong>TheHive Application Layer</strong>: 
    Exposes REST APIs and a web interface where alerts are created (from Shuffle automation), enriched, and managed by analysts as part of incident response.
  </li>
</ul>

<h3>5.3 Shuffle SOAR Integration</h3>
<ul>
  <li><strong>Shuffle</strong>: 
    Acts as the orchestration layer. Wazuh alerts are forwarded to Shuffle, which extracts observables (e.g., file hashes, process names) and enriches them using third-party threat intelligence (VirusTotal).
  </li>
  <li>Enriched alerts are then pushed to <strong>TheHive</strong> via API to automatically generate cases for investigation.</li>
  <li>Parallel workflows are configured in Shuffle to send <strong>email notifications</strong> to SOC analysts for immediate awareness.</li>
</ul>

<hr>

<h2>6. Mimikatz Simulation &amp; Detection</h2>
<p>
  This lab focuses specifically on <strong>Mimikatz</strong> (credential dumping). The steps performed:
</p>
<ul>
  <li>Executed Mimikatz on the Windows endpoint to simulate credential dumping (controlled, local lab environment only).</li>
  <li>Wazuh Agent captured process creation, command-line arguments, and any related Windows security events.</li>
  <li>Wazuh Manager generated an alert for the Mimikatz execution and forwarded the alert payload to Shuffle for enrichment.</li>
</ul>

<hr>

<h2>7. Detection &amp; Analysis (Workflow Results)</h2>

<p>The pipeline functioned in three main stages — <strong>Detection</strong>, <strong>Automation</strong>, and <strong>Enrichment &amp; Response</strong>. Each stage can be illustrated with screenshots for clarity.</p>
<h3>7.1. Detection (Wazuh)</h3>
<ul>
  <li>The Windows endpoint executed the <strong>Mimikatz tool</strong>, simulating credential theft.</li>
  <li>The <strong>Wazuh Agent</strong> on the endpoint captured the security event (process creation, command-line arguments, and event logs).</li>
  <li>These logs were forwarded to the <strong>Wazuh Manager</strong>, which processed and stored them through its internal components (Indexer &amp; Elasticsearch).</li>
  <li>An <strong>alert was raised</strong> in the <strong>Wazuh Dashboard</strong>, clearly identifying the suspicious activity.</li>
</ul>
<em>Wazuh Manager Mimikatz Alert Report</em> 
<img width="1907" height="3127" alt="wazuh report" src="https://github.com/user-attachments/assets/5e878f1d-3219-4b97-9910-abcf493df31b" />

<h3>7.2. Automation (Shuffle SOAR)</h3>
<ul>
  <li>Once the alert was generated, it was <strong>forwarded automatically to Shuffle SOAR</strong>.</li>
  <li>Shuffle extracted key details from the alert, such as the <strong>process name, file hash, and event metadata</strong>.</li>
  <li>Using a preconfigured workflow, Shuffle <strong>queried VirusTotal</strong> with the file hash to check whether the executable was flagged as malicious.</li>
</ul>
<em> Shuffle Workflow with VirusTotal Integration:</em>

<img width="1031" height="601" alt="shuffle workflow" src="https://github.com/user-attachments/assets/8b27fe8b-ac31-4b4f-93e3-cb7c80ab4c49" />

<h3>7.3. Enrichment &amp; Response (TheHive + Email Notification)</h3>
<ul>
  <li>If VirusTotal confirmed the file hash as suspicious or malicious, <strong>Shuffle triggered TheHive integration</strong>.</li>
  <li>A new <strong>case (alert ticket)</strong> was created inside TheHive, containing:
    <ul>
      <li>Event details from Wazuh</li>
      <li>Enrichment results from VirusTotal</li>
      <li>Timestamps and correlation identifiers</li>
    </ul>
  </li>
  <li>TheHive stored this case in its backend (Elasticsearch + Cassandra) and presented it on the dashboard for analyst review.</li>
  <li>Simultaneously, <strong>an email notification</strong> was sent to the SOC analyst team with case details, ensuring visibility and rapid response.</li>
</ul>
<em>TheHive Alert Page:</em>

<img width="1055" height="901" alt="hive alert" src="https://github.com/user-attachments/assets/33d79b91-e0ea-4868-b2b1-c9a5ad77defb" />

<em> Email Alert Notification:</em>

<img width="1552" height="642" alt="alert message" src="https://github.com/user-attachments/assets/77cf1c89-85c4-4adb-8830-a98aa7853968" />
<hr>

<h2>8. Conclusion &amp; Next Steps</h2>
<p>This SOC lab project demonstrated:</p>
<ul>
  <li>End-to-end <strong>log ingestion and detection</strong> using Wazuh.</li>
  <li>Automated <strong>alert enrichment</strong> with VirusTotal.</li>
  <li><strong>SOAR-driven incident response</strong> with Shuffle.</li>
  <li>Centralized <strong>case management</strong> in TheHive.</li>
</ul>

<p><strong>Next Steps:</strong></p>
<ul>
  <li>Expand coverage to more <strong>attack simulations</strong> (lateral movement, persistence).</li>
  <li>Build <strong>dashboards in Wazuh</strong> for continuous monitoring.</li>
  <li>Integrate with <strong>Slack/Teams</strong> for real-time SOC notifications.</li>
  <li>Enhance Shuffle workflows with <strong>automated containment actions</strong> (e.g., isolate endpoint).</li>
</ul>

<hr>
