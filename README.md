# YaraMonitor

YaraMonitor is a tool to continuously ingest, analyze, and alert on malware samples given a set of yara rules. The main design philosophy behind it is that it is extendable to monitor additional sources so long as the ingestion from that source can be automated via Python.

It currently monitors:
- MalwareBazaar recent uploads

## Structure

- `rules` = place yara rules here, do not create sub-folders
- `sources` = python scripts to ingest data from various sources, must be called by `monitor/main.py` in the `run_ingestion()` function
- `samples` = scripts in `sources` download samples to this directory, in a subfolder for each script (created at run time)

## Caution

The `samples` directory will contain live malware (with executable extensions).

## Requirements

- Python
- `pip install -r requirements.txt`

## Usage

- `monitor/main.py` is intended to be ran for long periods of time, polling MalwareBazaar every hour for new uploads
- It is recommended to use this within a Python venv
- By default, matches are only written to stdout. You can use `-d, --discord` to supply a Discord webhook and it will send a message with what rule and the path to the sample (it does not upload any files to Discord) 

```
git clone https://github.com/montysecurity/yaramonitor.git
cd YaraMonitor
# [Activate Python venv, optional, recommended]
python -m pip install -r requirements.txt
python main/main.py
```

- When running `main.py`, do it from the root folder of the repo (`yaramonitor`) by running `python monitor/main.py` (doing anything else will cause the program to not be able to find the `samples` directory)

## What happens when I run main.py

1. Removes all files from `samples` directory (optional, if `-w, --wipe` is supplied)
2. Poll MalwareBazaar and download all samples that were uploaded in the last hour, store in `samples/MalwareBazaar`
3. Loop through all files just downloaded, unzip them, delete the zip file, and scan them with all yara rules in `rules`
    - If a sample matches a rule, send alert (print to screen and/or Discord Webhook)
    - If a sample has no macthes, delete it
4. Sleep for 1 minute and repeat

## Intelligent Handling of Samples

So long as the program is running and memory is retained, the following are true:

- Samples that have a yara match are not deleted
- The process will not re-download samples that have already been downloaded and scanned, even if they have already been deleted
- The process will not re-scan samples that have already been scanned with the yara rules