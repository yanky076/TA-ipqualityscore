URL Checker
###########

This commands maps to Malicious URL Scanner API for IPQualityScore available [here](https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview). This custom command can help in following use cases

- **Phishing URL Detection** — Detect malicious URLs used for phishing campaigns and misleading advertising.
- **Malicious URL Scanning** — Identify URLs used for malware and viruses with live threat intelligence feeds that detect zero-day phishing links and suspicious behavior.
- **Parked Domain Detection** — Easily classify parked domains for sale.
- **Filter Email Spammer Domains** — Sift through suspicious emails with detection for domains confirmed as sending email SPAM. Further validate SPAM with real-time email threat scoring.
- **Abusive Domains** - Block emails from disposable email services and throwaway accounts. Pair with IP reputation checks for deeper insight.

Command Usage
-------------

The event need to have **url** field available for this command to be appended to the search. Example usage::

    ... | urlchecker

Following fields will be added to the event if the API call is successful

+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| Field        | Description                                                                                                                                                             | Possible Values  |
+==============+=========================================================================================================================================================================+==================+
| unsafe       | Is this domain suspected of being unsafe due to phishing, malware, spamming, or abusive behavior? View the confidence level by analyzing the "risk_score".              | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| domain       | Domain name of the final destination URL of the scanned link, after following all redirects.                                                                            | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| ip_address   | The IP address corresponding to the server of the domain name.                                                                                                          | string           |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| server       | The server banner of the domain's IP address. For example: "nginx/1.16.0". Value will be "N/A" if unavailable.                                                          | string           |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| content_type | MIME type of URL's content. For example "text/html; charset=UTF-8". Value will be "N/A" if unavailable.                                                                 | string           |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| risk_score   | The IPQS risk score which estimates the confidence level for malicious URL detection. Risk Scores 85+ are high risk, while Risk Scores = 100 are confirmed as accurate. | integer, 0 - 100 |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| status_code  | HTTP Status Code of the URL's response. This value should be "200" for a valid website. Value is "0" if URL is unreachable.                                             | integer          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| page_size    | Total number of bytes to download the URL's content. Value is "0" if URL is unreachable.                                                                                | integer          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| domain_rank  | Estimated popularity rank of website globally. Value is "0" if the domain is unranked or has low traffic.                                                               | integer          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| dns_valid    | The domain of the URL has valid DNS records.                                                                                                                            | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| suspicious   | Is this URL suspected of being malicious or used for phishing or abuse? Use in conjunction with the "risk_score" as a confidence level.                                 | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| phishing     | Is this URL associated with malicious phishing behavior?                                                                                                                | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| malware      | Is this URL associated with malware or viruses?                                                                                                                         | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| parking      | Is the domain of this URL currently parked with a for sale notice?                                                                                                      | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| spamming     | Is the domain of this URL associated with email SPAM or abusive email addresses?                                                                                        | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| message      | A generic status message, either success or some form of an error notice.                                                                                               | string           |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| success      | Was the request successful?                                                                                                                                             | boolean          |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+
| errors       | Array of errors which occurred while attempting to process this request.                                                                                                | array of strings |
+--------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------+

Available options
-----------------

Following options are available to **urlchecker** Splunk command

+------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------+
| Option           | Description                                                                                                                                                                                                                                                                                                                                                                    | Possible Values |
+==================+================================================================================================================================================================================================================================================================================================================================================================================+=================+
| strictness       | How strict should we scan this URL? Stricter checks may provide a higher false-positive rate. We recommend defaulting to level "0", the lowest strictness setting, and increasing to "1" or "2" depending on your levels of abuse.                                                                                                                                             | int (0-2)       |
+------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------+
