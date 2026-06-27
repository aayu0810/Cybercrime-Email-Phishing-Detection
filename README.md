# Email Phishing Detection System

## Project Overview

This project demonstrates how to extract email traffic from a packet capture using Wireshark and Python. The program filters SMTP, POP3, and IMAP traffic, extracts email information, detects phishing indicators, and generates a phishing report.

## Technologies Used

- Python 3.12
- PyShark
- Wireshark
- Regular Expressions (re)

## Project Files

- Cybercrime.py – Main Python program
- smtp_capture.pcapng – Sample packet capture
- phishing_report.txt – Generated analysis report

## Installation

Install the required library:

```bash
pip install pyshark
```

## Running the Program

```bash
python3.12 Cybercrime.py
```

## Features

- Filters SMTP, POP3, and IMAP traffic
- Extracts sender, recipient, subject, and email body
- Detects phishing keywords and suspicious sender domains
- Generates a phishing analysis report

## Output

The program generates **phishing_report.txt**, which contains the extracted email information and phishing detection results.
