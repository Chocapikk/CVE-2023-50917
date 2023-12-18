## Deep Dive: CVE-2023-50917 - Unmasking an Unauthenticated Remote Code Execution Flaw in MajorDoMo's Thumb Module

### Introduction

MajorDoMo, a beacon in Russian home automation, particularly favored by Raspberry Pi aficionados, has been a trusted name for over a decade. With over 380 stars on its [official GitHub repository](https://github.com/sergejey/majordomo) at the time of writing, its popularity is evident. However, lurking within its `thumb.php` module is a severe unauthenticated Remote Code Execution (RCE) vulnerability. This article intricately explores this critical flaw, detailing its roots, distinct exploitation methods, and possible ramifications.

### Disclosure Timeline:

- **October 28, 2023**: Initial discovery of the vulnerability (CVE-2023-50917).
- **October 29, 2023**: Contacted MajorDoMo team detailing the vulnerability.
- **November 6, 2023**: After no response from MajorDoMo's team for over a week, submitted a CVE request to the appropriate CNA.
- **November 14, 2023**: New attempt to contact the MajorDoMo team. Received a response from the team within a few hours. The patch has been applied.
- **December 15, 2023**: Public disclosure of CVE-2023-50917.

### Technical Background: The Vulnerable Code

The script `/modules/thumb/thumb.php` is primarily designed for thumbnail generation in MajorDoMo. It serves to facilitate the creation of thumbnails from various media sources. But within this benign purpose lies a significant vulnerability:

#### Key Code Snippets and Analysis:

1. **URL Decoding**:
    ```php
    $url = base64_decode($url);
    ```
    The script takes a base64 encoded `url` parameter and decodes it. This decoding process is pivotal, as it allows attackers to obfuscate their payloads, skirting around simple checks.

2. **Pattern Checks**:
    ```php
    if (preg_match('/^rtsp:/is', $url) || preg_match('/\/dev/', $url)) {
    ...
    }
    ```
    The script then checks if the decoded `url` adheres to specific patterns (`rtsp:` or `/dev`). This is a rudimentary check to decide whether to process the URL. With the help of base64 encoding, it becomes trivial for attackers to bypass this verification.

3. **Direct Command Construction**:
    ```php
    if ($_GET['transport']) {
        $stream_options = '-rtsp_transport ' . $_GET['transport'] . ' ' . $stream_options;
    }
    ```
    Here lies the crux of the vulnerability. The `transport` parameter is taken directly and embedded within a system command without adequate sanitization. This glaring oversight allows for arbitrary command injections. By crafting the `transport` parameter, an attacker can introduce and execute arbitrary commands. The subsequent command is executed via the `exec` function, which poses a significant security risk.

### The Core Vulnerability

The vulnerability's essence is the unchecked and unsanitized user input (from the `transport` parameter) that gets directly incorporated into a system command. This allows attackers to run arbitrary commands on the server, potentially taking full control of the MajorDoMo instance.

### Exploitation Avenues:

1. **Bypassing URL Validation**:
    The script's initial validation checks for patterns such as `rtsp:` or `/dev`. By using base64 encoded strings like `cnRzcDovL2EK` (decoding to `rtsp://a`), these checks can be easily bypassed.

2. **Command Injection via the `transport` Parameter**:
    The `transport` parameter is used directly within a system command. With no sanitization in place, this can be exploited for command injections, leading to RCE. For instance, the command `||echo; echo $(command_here)` can be used to break out of the intended command and execute any arbitrary command.

### Potential Impact

The severity of this RCE vulnerability is high. Given MajorDoMo's integral role in home automation, successful exploitation can result in an attacker compromising physical security systems, gaining access to surveillance cameras, or even taking control of other connected IoT devices.

### Recommendations for Mitigation

- **Thorough Input Validation**: It is essential to rigorously validate all inputs. This can prevent malicious payloads from being processed.
- **Sanitize Before Execution**: Inputs should be sanitized before being incorporated into any system commands.
- **Limit Direct Command Execution**: Prefer using built-in PHP functions or secure APIs over direct system command execution.

### Conclusion

This vulnerability underscores the importance of thorough code reviews and robust input validation. Even established software projects like MajorDoMo are not immune to critical vulnerabilities. The discovery serves as a reminder of the ever-present need for diligence and a proactive approach to security in all software development stages.
